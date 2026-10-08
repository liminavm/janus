// SPDX-License-Identifier: MIT OR Apache-2.0

//! Objects: keys and sealed data, their sensitive areas, how a primary one is made, and the
//! slots loaded ones live in.

use crate::alg::{Hash, MAX_DIGEST};
use crate::crypto::{self, Drbg, EccPrivate, RsaPrivate};
use crate::handle::{handle_type, ht};
use crate::hierarchy::Hierarchy;
use crate::marshal::{Marshal, Tpm2b, Unmarshal};
use crate::rc::{At, Fmt0, Fmt1, Rc};
use crate::sequence::HashSequence;
use crate::types::{
    EccPoint, EccScheme, KeyedHashScheme, MAX_ECC_KEY_BYTES, MAX_SYM_DATA, Name2b, Public,
    PublicKind, RsaScheme, Secret, SensitiveCreate, SymDefObject, SymObject,
};
use crate::wire::{Blame as _, Buf, Reader, Writer};
use zeroize::Zeroizing;

/// Largest symmetric key (AES-128).
pub const MAX_SYM_KEY_BYTES: usize = 16;
/// Largest RSA private prime (half a 2048-bit modulus).
pub const MAX_RSA_PRIME_BYTES: usize = 128;

wire_union! {
    /// `TPMU_SENSITIVE_COMPOSITE` with the type that selects it.
    pub enum SensitiveKind: u16 [Fmt1::Type] {
        Rsa = crate::alg::id::RSA => Secret<MAX_RSA_PRIME_BYTES>,
        KeyedHash = crate::alg::id::KEYEDHASH => Secret<MAX_SYM_DATA>,
        Ecc = crate::alg::id::ECC => Secret<MAX_ECC_KEY_BYTES>,
        SymCipher = crate::alg::id::SYMCIPHER => Secret<MAX_SYM_KEY_BYTES>,
    }
}

/// `TPMT_SENSITIVE`: an object's authorization value, its seed value (the obfuscation value of
/// a symmetric object, or the secret a parent derives its children's protection from) and its
/// private material.
pub struct Sensitive {
    pub auth: Secret<MAX_DIGEST>,
    pub seed: Secret<MAX_DIGEST>,
    pub kind: SensitiveKind,
}

impl Marshal for Sensitive {
    fn write(&self, w: &mut Writer) {
        self.kind.selector().write(w);
        self.auth.write(w);
        self.seed.write(w);
        self.kind.write_body(w);
    }
}

impl Unmarshal for Sensitive {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let selector = u16::read(r)?;
        if !SensitiveKind::is_selector(selector) {
            return Err(Fmt1::Type);
        }
        let auth = Secret::read(r)?;
        let seed = Secret::read(r)?;
        let kind = SensitiveKind::read_body(selector, r)?;
        Ok(Sensitive { auth, seed, kind })
    }
}

/// A loaded object. Its marshalled form is also what a saved context of it carries.
pub struct Object {
    pub public: Public,
    pub sensitive: Sensitive,
    /// The hierarchy it belongs to: whose proof protects its saved contexts, and whose reset
    /// makes it unloadable (the null hierarchy's, at every TPM Reset).
    pub hierarchy: Hierarchy,
    /// `H(parent's qualified name || name)`: the object's place in its hierarchy, which its own
    /// public area cannot say, so it is fixed when the object is created or loaded.
    pub qualified_name: Name2b,
}

impl Marshal for Object {
    fn write(&self, w: &mut Writer) {
        self.public.write(w);
        self.sensitive.write(w);
        self.hierarchy.write(w);
        self.qualified_name.write(w);
    }
}

/// Reading an object back checks what every holder of one relies on: its private part is of
/// its public part's type (`TPM_RC_TYPE`), and an ECC private part is a valid scalar
/// (`TPM_RC_KEY`).
impl Unmarshal for Object {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let public = Public::read(r)?;
        let sensitive = Sensitive::read(r)?;
        if sensitive.kind.selector() != public.kind.selector() {
            return Err(Fmt1::Type);
        }
        if let SensitiveKind::Ecc(d) = &sensitive.kind
            && EccPrivate::from_bytes(d.as_slice()).is_none()
        {
            return Err(Fmt1::Key);
        }
        let hierarchy = Hierarchy::read(r)?;
        let qualified_name = Name2b::read(r)?;
        Ok(Object { public, sensitive, hierarchy, qualified_name })
    }
}

impl Object {
    pub fn name(&self) -> Name2b {
        self.public.name()
    }

    /// A second copy, for `TPM2_EvictControl`, which leaves the transient object loaded. Made
    /// through the marshalled form a saved context carries, so the copy has passed the checks
    /// any object read back must pass. (`Object` has no `Clone`: key material is copied only on
    /// purpose.)
    pub fn duplicate(&self) -> Object {
        let mut w = Writer::new();
        self.write(&mut w);
        let bytes = Zeroizing::new(w.into_vec());
        let mut r = Reader::new(&bytes);
        let o = Object::read(&mut r).expect("an object reads back what it wrote");
        r.finish().expect("an object reads back exactly what it wrote");
        o
    }
}

/// Why a public area cannot be created, as `TPMT_PUBLIC` validation reports it: a format-1
/// code the caller positions on the parameter that carried the area.
pub type Invalid = Fmt1;

/// The checks `TPM2_CreatePrimary` (and later `TPM2_Create`) make on a template before using
/// it: the reference's `CreateChecks`, `PublicAttributesValidation` and `SchemeChecks`, in
/// their order, for a primary object (whose parent counts as fixedTPM) or a child of `parent`.
pub fn validate_template(
    public: &Public,
    data_size: usize,
    parent: Option<&Object>,
) -> Result<(), Invalid> {
    let a = public.attributes;
    // The caller provides the data exactly when the TPM does not.
    if !a.sensitive_data_origin() && data_size == 0 {
        return Err(Fmt1::Attributes);
    }
    if parent.is_some() && a.sensitive_data_origin() && data_size != 0 {
        return Err(Fmt1::Attributes);
    }
    match &public.kind {
        PublicKind::KeyedHash(_) | PublicKind::SymCipher(_) => {
            if let PublicKind::KeyedHash(_) = public.kind
                && !a.sign_encrypt()
                && !a.decrypt()
                && a.sensitive_data_origin()
            {
                return Err(Fmt1::Attributes);
            }
            if a.restricted() && !a.sensitive_data_origin() && (a.fixed_parent() || a.fixed_tpm()) {
                return Err(Fmt1::Attributes);
            }
        }
        PublicKind::Ecc(_) | PublicKind::Rsa(_) => {
            if !a.sensitive_data_origin() {
                return Err(Fmt1::Attributes);
            }
        }
    }
    validate_public(public, parent)
}

/// The checks every object's public area passes, created or loaded
/// (`PublicAttributesValidation`, which ends in `SchemeChecks`). nameAlg cannot be NULL:
/// `Hash` has no NULL.
pub fn validate_public(public: &Public, parent: Option<&Object>) -> Result<(), Invalid> {
    let a = public.attributes;
    if !public.auth_policy.as_slice().is_empty()
        && public.auth_policy.as_slice().len() != public.name_alg.size()
    {
        return Err(Fmt1::Size);
    }
    let parent_fixed_tpm = parent.is_none_or(|p| p.public.attributes.fixed_tpm());
    if parent_fixed_tpm {
        if a.fixed_parent() != a.fixed_tpm() {
            return Err(Fmt1::Attributes);
        }
    } else if a.fixed_tpm() {
        return Err(Fmt1::Attributes);
    }
    if a.sign_encrypt() == a.decrypt() {
        if a.restricted() {
            return Err(Fmt1::Attributes);
        }
        if !matches!(public.kind, PublicKind::KeyedHash(_)) && !a.sign_encrypt() {
            return Err(Fmt1::Attributes);
        }
    }
    if a.fixed_tpm() && a.encrypted_duplication() {
        return Err(Fmt1::Attributes);
    }
    if let Some(p) = parent
        && !p.public.attributes.fixed_tpm()
        && a.encrypted_duplication() != p.public.attributes.encrypted_duplication()
    {
        return Err(Fmt1::Attributes);
    }
    scheme_checks(public, parent)
}

fn scheme_checks(public: &Public, parent: Option<&Object>) -> Result<(), Invalid> {
    let a = public.attributes;
    let symmetric = match &public.kind {
        PublicKind::SymCipher(s) => {
            // Only CFB is implemented, which is a valid decryption mode.
            let SymObject::Aes(_) = s.sym;
            None
        }
        PublicKind::KeyedHash(k) => {
            let scheme = k.scheme;
            if a.sign_encrypt() == a.decrypt() {
                if scheme != KeyedHashScheme::Null(()) {
                    return Err(Fmt1::Scheme);
                }
            } else if a.sign_encrypt() {
                if !matches!(scheme, KeyedHashScheme::Hmac(_)) {
                    return Err(Fmt1::Scheme);
                }
            } else {
                // A decrypting keyed hash needs the XOR scheme, which is not implemented.
                return Err(Fmt1::Scheme);
            }
            None
        }
        PublicKind::Ecc(e) => {
            let signs = matches!(e.parms.scheme, EccScheme::Ecdsa(_));
            let decrypts = matches!(e.parms.scheme, EccScheme::Ecdh(_));
            let null = e.parms.scheme == EccScheme::Null(());
            asym_scheme_checks(a, null, signs, decrypts)?;
            Some(e.parms.symmetric)
        }
        PublicKind::Rsa(r) => {
            let signs = matches!(r.parms.scheme, RsaScheme::Rsassa(_) | RsaScheme::Rsapss(_));
            let decrypts = matches!(r.parms.scheme, RsaScheme::Rsaes(()) | RsaScheme::Oaep(_));
            let null = r.parms.scheme == RsaScheme::Null(());
            asym_scheme_checks(a, null, signs, decrypts)?;
            Some(r.parms.symmetric)
        }
    };
    if let Some(sym) = symmetric {
        let parent_like = a.restricted() && a.decrypt();
        if !parent_like && sym != SymDefObject::Null(()) {
            return Err(Fmt1::Symmetric);
        }
        if parent_like {
            if sym == SymDefObject::Null(()) {
                return Err(Fmt1::Symmetric);
            }
            if let Some(p) = parent
                && a.fixed_parent()
            {
                if public.name_alg != p.public.name_alg {
                    return Err(Fmt1::Hash);
                }
                if Some(sym) != parent_symmetric(p) {
                    return Err(Fmt1::Symmetric);
                }
            }
        }
    }
    Ok(())
}

/// The asymmetric half of `SchemeChecks`: a key that both signs and decrypts (or neither) has
/// no scheme; a restricted key's scheme is its one use.
fn asym_scheme_checks(
    a: crate::types::ObjectAttributes,
    null: bool,
    signs: bool,
    decrypts: bool,
) -> Result<(), Invalid> {
    if a.sign_encrypt() == a.decrypt() {
        if !null {
            return Err(Fmt1::Scheme);
        }
    } else if a.sign_encrypt() {
        // A signing scheme always names a hash here: the types have no NULL hash.
        if !signs && (a.restricted() || !null) {
            return Err(Fmt1::Scheme);
        }
    } else if a.restricted() {
        if !null {
            return Err(Fmt1::Scheme);
        }
    } else if !null && !decrypts {
        return Err(Fmt1::Scheme);
    }
    Ok(())
}

fn parent_symmetric(p: &Object) -> Option<SymDefObject> {
    match &p.public.kind {
        PublicKind::Ecc(e) => Some(e.parms.symmetric),
        PublicKind::Rsa(r) => Some(r.parms.symmetric),
        PublicKind::KeyedHash(_) | PublicKind::SymCipher(_) => None,
    }
}

/// The label a primary object's generator is instantiated under (`PRIMARY_OBJECT_CREATION`).
const PRIMARY_LABEL: &[u8] = b"Primary Object Creation";

/// Creates a primary object: everything the TPM generates is drawn from a generator seeded by
/// the hierarchy's seed, the template's name and the caller's sensitive data, so the same
/// template under the same seed gives the same object every time.
///
/// `template` has passed [`validate_template`].
pub fn create_primary(
    seed: &[u8],
    hierarchy: Hierarchy,
    template: Public,
    sensitive: SensitiveCreate,
) -> Result<Object, Unsupported> {
    let template_name = template.name();
    let mut drbg =
        Drbg::new(seed, PRIMARY_LABEL, &[template_name.as_slice(), sensitive.data.as_slice()]);
    generate(template, sensitive, &mut drbg, hierarchy, &hierarchy.handle().to_be_bytes())
}

/// Creates an ordinary object under `parent` (`TPM2_Create`), its secrets drawn from `drbg`,
/// which the caller seeds from the platform's randomness.
pub fn create(
    parent: &Object,
    template: Public,
    sensitive: SensitiveCreate,
    drbg: &mut Drbg,
) -> Result<Object, Unsupported> {
    generate(template, sensitive, drbg, parent.hierarchy, parent.qualified_name.as_slice())
}

fn generate(
    mut template: Public,
    sensitive: SensitiveCreate,
    drbg: &mut Drbg,
    hierarchy: Hierarchy,
    parent_qualified_name: &[u8],
) -> Result<Object, Unsupported> {
    let name_alg = template.name_alg;
    let digest_size = name_alg.size();
    let a = template.attributes;

    // A parent's seed value, from which its children's protection keys are derived; a
    // symmetric object's obfuscation value. Drawn first, so a key's private part does not move
    // when the seed is added or removed.
    let mut seed_value = vec![0u8; digest_size];
    let needs_seed = a.restricted() && a.decrypt()
        || matches!(template.kind, PublicKind::KeyedHash(_) | PublicKind::SymCipher(_));
    if needs_seed {
        drbg.fill(&mut seed_value);
    } else {
        seed_value.clear();
    }
    let seed_secret = secret(&seed_value);
    zeroize::Zeroize::zeroize(&mut seed_value);

    let kind = match &mut template.kind {
        PublicKind::Ecc(e) => {
            let key = EccPrivate::generate(drbg);
            let (x, y) = key.public();
            e.unique = EccPoint {
                x: Buf::from_slice(&x).expect("a P-256 coordinate fits"),
                y: Buf::from_slice(&y).expect("a P-256 coordinate fits"),
            };
            SensitiveKind::Ecc(secret(&key.to_bytes()[..]))
        }
        PublicKind::KeyedHash(k) => {
            let bits = if a.sensitive_data_origin() {
                let mut b = zeroize::Zeroizing::new(vec![0u8; digest_size]);
                drbg.fill(&mut b);
                secret(&b)
            } else {
                secret(sensitive.data.as_slice())
            };
            k.unique = unique_digest(name_alg, seed_secret.as_slice(), bits.as_slice());
            SensitiveKind::KeyedHash(bits)
        }
        PublicKind::SymCipher(s) => {
            let key = if a.sensitive_data_origin() {
                let mut b = zeroize::Zeroizing::new([0u8; MAX_SYM_KEY_BYTES]);
                drbg.fill(&mut b[..]);
                secret(&b[..])
            } else {
                if sensitive.data.as_slice().len() != MAX_SYM_KEY_BYTES {
                    return Err(Unsupported::KeySize);
                }
                secret(sensitive.data.as_slice())
            };
            s.unique = unique_digest(name_alg, seed_secret.as_slice(), key.as_slice());
            SensitiveKind::SymCipher(key)
        }
        PublicKind::Rsa(r) => {
            let e = crypto::rsa_exponent(r.parms.exponent).ok_or(Unsupported::Range)?;
            let key = RsaPrivate::generate(drbg, e);
            r.unique = Buf::from_slice(&key.modulus()).expect("a 2048-bit modulus fits");
            SensitiveKind::Rsa(secret(&key.prime()))
        }
    };
    let auth = secret(trim(sensitive.user_auth.as_slice()));
    let qualified_name = qualified_name(name_alg, parent_qualified_name, &template.name());
    Ok(Object {
        public: template,
        sensitive: Sensitive { auth, seed: seed_secret, kind },
        hierarchy,
        qualified_name,
    })
}

/// Whether `o` can be a parent (`ObjectIsParent`): a restricted decryption key, which
/// [`validate_template`] has made sure has a symmetric algorithm for its children.
pub fn is_parent(o: &Object) -> bool {
    let a = o.public.attributes;
    a.restricted() && a.decrypt() && !a.sign_encrypt()
}

/// The largest `TPM2B_PRIVATE` janus makes or accepts: the integrity HMAC, the IV and the
/// encrypted `TPM2B_SENSITIVE` of the largest object (an RSA one).
pub const MAX_PRIVATE: usize = (2 + MAX_DIGEST) + (2 + 16) + (2 + MAX_SENSITIVE);
/// The largest marshalled `TPMT_SENSITIVE`.
const MAX_SENSITIVE: usize = 2 + (2 + MAX_DIGEST) + (2 + MAX_DIGEST) + (2 + MAX_RSA_PRIME_BYTES);

/// `TPM2B_PRIVATE`.
pub type Private = Buf<MAX_PRIVATE>;

/// The keys a parent protects a child's private area with (Part 1 §23.3):
/// `KDFa(parent nameAlg, seedValue, "STORAGE", name, empty, 128)` for AES-128-CFB, and
/// `KDFa(parent nameAlg, seedValue, "INTEGRITY", empty, empty, digest bits)` for the HMAC.
fn protection(parent: &Object, name: &[u8]) -> (Zeroizing<[u8; 16]>, Zeroizing<Vec<u8>>) {
    let h = parent.public.name_alg;
    let seed = parent.sensitive.seed.as_slice();
    let bits = crypto::kdfa(h, seed, b"STORAGE", name, &[], 128);
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&bits);
    let hmac_key = crypto::kdfa(h, seed, b"INTEGRITY", &[], &[], (h.size() * 8) as u32);
    (key, hmac_key)
}

/// Wraps `child`'s sensitive area for storage outside the TPM (`SensitiveToPrivate`):
/// `TPM2B integrity || TPM2B iv || AES-CFB(TPM2B_SENSITIVE)`, the integrity being
/// `HMAC(integrityKey, iv || encrypted || name)`.
pub fn wrap(parent: &Object, child: &Object, iv: [u8; 16]) -> Private {
    let name = child.name();
    let mut inner = Writer::new();
    Tpm2b(&child.sensitive).write(&mut inner);
    let mut data = Zeroizing::new(inner.into_vec());
    let (key, hmac_key) = protection(parent, name.as_slice());
    crypto::aes128_cfb_encrypt(&key, &iv, &mut data);
    let mut ivd = Writer::new();
    ivd.tpm2b(&iv);
    let ivd = ivd.into_vec();
    let tag = crypto::hmac(parent.public.name_alg, &hmac_key, &[&ivd, &data, name.as_slice()]);
    let mut out = Writer::new();
    out.tpm2b(&tag);
    out.bytes(&ivd);
    out.bytes(&data);
    Buf::from_slice(&out.into_vec()).expect("a wrapped sensitive area is within MAX_PRIVATE")
}

/// Unwraps a private area wrapped for the object named `name` under `parent`
/// (`PrivateToSensitive`). A malformed or forged outer layer is a format-1 error at `at`, the
/// private area's parameter; a sensitive area that verified but does not decode is
/// `TPM_RC_SENSITIVE`.
pub fn unwrap(parent: &Object, name: &Name2b, private: &[u8], at: At) -> Result<Sensitive, Rc> {
    let mut r = Reader::new(private);
    let tag = r.tpm2b::<MAX_DIGEST>().at(at)?;
    let rest = r.bytes(r.remaining()).expect("remaining bytes are there");
    let (key, hmac_key) = protection(parent, name.as_slice());
    let expected = crypto::hmac(parent.public.name_alg, &hmac_key, &[rest, name.as_slice()]);
    if !crypto::constant_time_eq(&expected, tag.get()) {
        return Err(Rc::Fmt1(Fmt1::Integrity, Some(at)));
    }
    let mut r = Reader::new(rest);
    let iv = r.tpm2b::<16>().at(at)?;
    let iv: [u8; 16] = iv.get().try_into().map_err(|_| Rc::Fmt1(Fmt1::Value, Some(at)))?;
    let mut data = Zeroizing::new(r.bytes(r.remaining()).expect("there").to_vec());
    crypto::aes128_cfb_decrypt(&key, &iv, &mut data);
    let mut r = Reader::new(&data);
    let sensitive = Tpm2b::<Sensitive>::read(&mut r).map_err(|_| Fmt0::Sensitive)?.0;
    r.finish().map_err(|_| Fmt0::Sensitive)?;
    Ok(sensitive)
}

/// Builds a loaded object from a public area and the sensitive area unwrapped for it under
/// `parent` (`ObjectLoad`), blaming `private` and `public` (the command's parameters) as the
/// reference does.
///
/// The reference checks that the two areas belong together (`CryptValidateKeys`) only under a
/// parent that is not fixedTPM; janus checks under every parent. Under a fixedTPM parent the
/// integrity check has already proved janus wrapped the pair, so the answers can differ only
/// for a pair no such parent's integrity check passes.
pub fn load(
    parent: &Object,
    public: Public,
    sensitive: Sensitive,
    private: At,
    public_at: At,
) -> Result<Object, Rc> {
    let digest_size = public.name_alg.size();
    let seed = sensitive.seed.as_slice();
    if seed.len() > digest_size {
        return Err(Rc::Fmt1(Fmt1::KeySize, Some(private)));
    }
    validate_public(&public, Some(parent)).at(public_at)?;
    let key_size = Rc::Fmt1(Fmt1::KeySize, Some(private));
    let binding = Rc::Fmt1(Fmt1::Binding, None);
    match (&public.kind, &sensitive.kind) {
        (PublicKind::Ecc(e), SensitiveKind::Ecc(d)) => {
            let key = EccPrivate::from_bytes(d.as_slice()).ok_or(Rc::Fmt1(Fmt1::KeySize, None))?;
            let (x, y) = key.public();
            if e.unique.x.as_slice() != x || e.unique.y.as_slice() != y {
                return Err(binding);
            }
        }
        (PublicKind::KeyedHash(k), SensitiveKind::KeyedHash(bits)) => {
            let max = match k.scheme {
                KeyedHashScheme::Hmac(h) => h.block_size(),
                KeyedHashScheme::Null(()) => MAX_SYM_DATA,
            };
            if bits.as_slice().len() > max || seed.len() != digest_size {
                return Err(key_size);
            }
            if k.unique != unique_digest(public.name_alg, seed, bits.as_slice()) {
                return Err(binding);
            }
        }
        (PublicKind::SymCipher(s), SensitiveKind::SymCipher(key)) => {
            if key.as_slice().len() != MAX_SYM_KEY_BYTES || seed.len() != digest_size {
                return Err(key_size);
            }
            if s.unique != unique_digest(public.name_alg, seed, key.as_slice()) {
                return Err(binding);
            }
        }
        (PublicKind::Rsa(r), SensitiveKind::Rsa(prime)) => {
            let n = r.unique.as_slice();
            if n.len() != crypto::RSA_MODULUS_BYTES || n[0] < 0x80 {
                return Err(Rc::Fmt1(Fmt1::Key, Some(public_at)));
            }
            if r.parms.exponent != 0 && r.parms.exponent < 7 {
                return Err(Rc::Fmt1(Fmt1::Value, Some(public_at)));
            }
            let p = prime.as_slice();
            if p.len() != crypto::RSA_PRIME_BYTES || p[0] < 0x80 {
                return Err(key_size);
            }
            // CryptRsaLoadPrivateExponent: the prime must divide the modulus.
            if RsaPrivate::from_prime(n, rsa_exponent_of(r.parms.exponent), p).is_none() {
                return Err(binding);
            }
        }
        _ => return Err(Rc::Fmt1(Fmt1::Type, Some(private))),
    }
    let a = public.attributes;
    if a.restricted() && a.decrypt() && (seed.len() < digest_size / 2 || seed.len() > digest_size) {
        return Err(Rc::Fmt1(Fmt1::Size, Some(private)));
    }
    let qualified_name =
        qualified_name(public.name_alg, parent.qualified_name.as_slice(), &public.name());
    Ok(Object { public, sensitive, hierarchy: parent.hierarchy, qualified_name })
}

/// The exponent an RSA public area's `exponent` field stands for: zero is 65537.
fn rsa_exponent_of(e: u32) -> u32 {
    if e == 0 { crypto::RSA_DEFAULT_EXPONENT } else { e }
}

impl Object {
    /// An RSA object's key. Its parts were checked to belong together when it was created or
    /// loaded, so this is `None` only for an object that is not RSA.
    pub fn rsa(&self) -> Option<RsaPrivate> {
        let (PublicKind::Rsa(r), SensitiveKind::Rsa(p)) = (&self.public.kind, &self.sensitive.kind)
        else {
            return None;
        };
        let key = RsaPrivate::from_prime(
            r.unique.as_slice(),
            rsa_exponent_of(r.parms.exponent),
            p.as_slice(),
        );
        Some(key.expect("an RSA object's prime divides its modulus"))
    }

    /// An ECC object's private key, likewise.
    pub fn ecc(&self) -> Option<EccPrivate> {
        let SensitiveKind::Ecc(d) = &self.sensitive.kind else {
            return None;
        };
        Some(EccPrivate::from_bytes(d.as_slice()).expect("an ECC object's scalar is valid"))
    }
}

/// `nameAlg || H(parent's qualified name || name)`. A primary object's parent is its hierarchy,
/// whose qualified name is its handle.
pub fn qualified_name(h: Hash, parent_qn: &[u8], name: &Name2b) -> Name2b {
    let d = h.digest(&[parent_qn, name.as_slice()]);
    let mut w = Writer::new();
    h.write(&mut w);
    w.bytes(d.as_slice());
    Name2b::from_slice(&w.into_vec()).expect("a qualified name is a TPMT_HA")
}

/// Why [`create_primary`] or [`create`] makes nothing from a template that validated.
#[derive(Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// An RSA exponent that is neither zero nor a prime of at least 65537 (`TPM_RC_RANGE`).
    Range,
    /// Caller-provided symmetric key of the wrong size (`TPM_RC_KEY_SIZE`).
    KeySize,
}

/// The unique field of a symmetric or keyed-hash object: `H(seedValue || sensitive)`.
fn unique_digest(h: Hash, seed: &[u8], sensitive: &[u8]) -> crate::types::Digest2b {
    let d = h.digest(&[seed, sensitive]);
    Buf::from_slice(d.as_slice()).expect("a digest fits a TPM2B_DIGEST")
}

fn trim(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && b[end - 1] == 0 {
        end -= 1;
    }
    &b[..end]
}

/// A secret of bytes the engine made, which fit by construction.
fn secret<const MAX: usize>(b: &[u8]) -> Secret<MAX> {
    Secret::from_slice(b).expect("engine-made secret exceeds its bound")
}

/// The transient object slots (`MAX_LOADED_OBJECTS`).
pub const MAX_LOADED_OBJECTS: usize = 3;

/// The first transient handle (`TRANSIENT_FIRST`).
pub const TRANSIENT_FIRST: u32 = 0x8000_0000;

/// What a transient object slot holds: a key or sealed data, or a running hash sequence.
pub enum Occupant {
    Key(Box<Object>),
    Sequence(Box<HashSequence>),
}

/// Loaded transient objects, by slot. A slot's handle is `TRANSIENT_FIRST + slot`.
#[derive(Default)]
pub struct Objects {
    slots: [Option<Occupant>; MAX_LOADED_OBJECTS],
}

/// A handle of a loaded key or sealed object, transient or persistent. Only [`Objects`] and
/// [`Evicted`] make one, by finding such an object, so a handler holding one knows the object
/// was there when the command started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded(Place);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    Slot(usize),
    Persistent(u32),
}

impl Loaded {
    pub fn handle(self) -> u32 {
        match self.0 {
            Place::Slot(s) => TRANSIENT_FIRST + s as u32,
            Place::Persistent(h) => h,
        }
    }

    pub fn is_persistent(self) -> bool {
        matches!(self.0, Place::Persistent(_))
    }
}

/// The object `l` names, in whichever store holds it.
pub fn get<'a>(objects: &'a Objects, evicted: &'a Evicted, l: Loaded) -> &'a Object {
    match l.0 {
        Place::Slot(s) => match &objects.slots[s] {
            Some(Occupant::Key(o)) => o,
            _ => unreachable!("a Loaded handle names a slot holding an object"),
        },
        Place::Persistent(h) => {
            evicted.objects.get(&h).expect("a Loaded handle names a persistent object")
        }
    }
}

/// The first platform persistent handle (`PLATFORM_PERSISTENT`).
pub const PLATFORM_PERSISTENT: u32 = 0x8180_0000;
/// Persistent objects janus keeps (`TPM_PT_HR_PERSISTENT_MIN`). An eighth is
/// `TPM_RC_NV_SPACE`.
pub const MAX_PERSISTENT_OBJECTS: usize = 7;

/// Objects made persistent by `TPM2_EvictControl`, by handle. They survive every reset.
#[derive(Default)]
pub struct Evicted {
    objects: std::collections::BTreeMap<u32, Box<Object>>,
}

impl Evicted {
    pub fn find(&self, h: u32) -> Option<Loaded> {
        self.objects.contains_key(&h).then_some(Loaded(Place::Persistent(h)))
    }

    pub fn contains(&self, h: u32) -> bool {
        self.objects.contains_key(&h)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Makes `o` persistent at `h`. The caller has checked `h` is free and the store not full.
    pub fn insert(&mut self, h: u32, o: Object) {
        debug_assert!(!self.objects.contains_key(&h) && self.len() < MAX_PERSISTENT_OBJECTS);
        self.objects.insert(h, Box::new(o));
    }

    pub fn remove(&mut self, l: Loaded) {
        if let Place::Persistent(h) = l.0 {
            self.objects.remove(&h);
        }
    }

    /// The persistent handles at or above `from`, in order.
    pub fn handles_from(&self, from: u32) -> Vec<u32> {
        self.objects.range(from..).map(|(h, _)| *h).collect()
    }
}

/// A handle of a running hash sequence, likewise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceSlot(usize);

impl SequenceSlot {
    pub fn handle(self) -> u32 {
        TRANSIENT_FIRST + self.0 as u32
    }
}

fn slot_of(h: u32) -> Option<usize> {
    if handle_type(h) != ht::TRANSIENT {
        return None;
    }
    let slot = h.checked_sub(TRANSIENT_FIRST)? as usize;
    (slot < MAX_LOADED_OBJECTS).then_some(slot)
}

impl Objects {
    /// The loaded key or sealed object `h` names: `None` when `h` is not a transient handle,
    /// or its slot is empty or holds a sequence.
    pub fn find(&self, h: u32) -> Option<Loaded> {
        let slot = slot_of(h)?;
        matches!(self.slots[slot], Some(Occupant::Key(_))).then_some(Loaded(Place::Slot(slot)))
    }

    /// The running sequence `h` names, likewise.
    pub fn find_sequence(&self, h: u32) -> Option<SequenceSlot> {
        let slot = slot_of(h)?;
        matches!(self.slots[slot], Some(Occupant::Sequence(_))).then_some(SequenceSlot(slot))
    }

    /// Whether anything is loaded under `h`.
    pub fn is_occupied(&self, h: u32) -> bool {
        slot_of(h).is_some_and(|s| self.slots[s].is_some())
    }

    pub fn sequence(&self, s: SequenceSlot) -> &HashSequence {
        match &self.slots[s.0] {
            Some(Occupant::Sequence(q)) => q,
            _ => unreachable!("a SequenceSlot names a slot holding a sequence"),
        }
    }

    pub fn sequence_mut(&mut self, s: SequenceSlot) -> &mut HashSequence {
        match &mut self.slots[s.0] {
            Some(Occupant::Sequence(q)) => q,
            _ => unreachable!("a SequenceSlot names a slot holding a sequence"),
        }
    }

    /// Puts `o` in the lowest free slot; `None` when every slot is taken
    /// (`TPM_RC_OBJECT_MEMORY`).
    pub fn insert(&mut self, o: Object) -> Option<Loaded> {
        self.place(Occupant::Key(Box::new(o))).map(|s| Loaded(Place::Slot(s)))
    }

    pub fn insert_sequence(&mut self, q: HashSequence) -> Option<SequenceSlot> {
        self.place(Occupant::Sequence(Box::new(q))).map(SequenceSlot)
    }

    fn place(&mut self, o: Occupant) -> Option<usize> {
        let slot = self.slots.iter().position(Option::is_none)?;
        self.slots[slot] = Some(o);
        Some(slot)
    }

    /// Empties the slot `h` names, returning what was in it.
    pub fn remove(&mut self, h: u32) -> Option<Occupant> {
        self.slots[slot_of(h)?].take()
    }

    pub fn loaded_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// The handles of loaded objects of either kind at or above `from`, in order.
    pub fn handles_from(&self, from: u32) -> Vec<u32> {
        (0..MAX_LOADED_OBJECTS)
            .filter(|&i| self.slots[i].is_some())
            .map(|i| TRANSIENT_FIRST + i as u32)
            .filter(|h| *h >= from)
            .collect()
    }
}

/// In the state file: the number of persistent objects, then each one's handle and object.
impl Marshal for Evicted {
    fn write(&self, w: &mut Writer) {
        w.u32(self.objects.len() as u32);
        for (h, o) in &self.objects {
            w.u32(*h);
            o.write(w);
        }
    }
}

impl Unmarshal for Evicted {
    /// No more objects than the TPM holds, each at a persistent handle, in ascending order as
    /// `write` writes them, so each handle is used once and a state reads back to the same
    /// bytes.
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let n = r.u32()? as usize;
        if n > MAX_PERSISTENT_OBJECTS {
            return Err(Fmt1::Size);
        }
        let mut objects = std::collections::BTreeMap::new();
        for _ in 0..n {
            let h = r.u32()?;
            if handle_type(h) != ht::PERSISTENT {
                return Err(Fmt1::Value);
            }
            if objects.last_key_value().is_some_and(|(last, _)| *last >= h) {
                return Err(Fmt1::Value);
            }
            objects.insert(h, Box::new(Object::read(r)?));
        }
        Ok(Evicted { objects })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::read_prefix;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn kernel_template() -> Public {
        read_prefix::<Public>(&hex("0023000b00030472000000060080004300100003001000000000"))
            .unwrap()
            .0
    }

    fn empty_sensitive() -> SensitiveCreate {
        read_prefix::<SensitiveCreate>(&[0, 0, 0, 0]).unwrap().0
    }

    #[test]
    fn the_kernels_template_is_valid_and_its_key_is_reproducible() {
        let t = kernel_template();
        validate_template(&t, 0, None).unwrap();
        let a = create_primary(&[1; 32], Hierarchy::Null, t.clone(), empty_sensitive()).unwrap();
        let b = create_primary(&[1; 32], Hierarchy::Null, t.clone(), empty_sensitive()).unwrap();
        assert_eq!(a.name(), b.name());
        let attrs = a.public.attributes;
        assert!(attrs.restricted() && attrs.decrypt() && !a.sensitive.seed.as_slice().is_empty());
        let c = create_primary(&[2; 32], Hierarchy::Null, t, empty_sensitive()).unwrap();
        assert_ne!(a.name(), c.name());
    }

    #[test]
    fn an_object_whose_parts_disagree_does_not_read() {
        let o = create_primary(&[1; 32], Hierarchy::Null, kernel_template(), empty_sensitive())
            .unwrap();
        let mut w = Writer::new();
        o.write(&mut w);
        let bytes = w.into_vec();
        assert!(read_prefix::<Object>(&bytes).is_ok());
        // The sensitive area's selector follows the public area; make it KEYEDHASH.
        let public_len = {
            let mut w = Writer::new();
            o.public.write(&mut w);
            w.len()
        };
        let mut bad = bytes.clone();
        bad[public_len..public_len + 2].copy_from_slice(&crate::alg::id::KEYEDHASH.to_be_bytes());
        assert_eq!(read_prefix::<Object>(&bad).err(), Some(Fmt1::Type));
    }

    #[test]
    fn template_checks_follow_the_reference() {
        let mut t = kernel_template();
        // fixedTPM without fixedParent, for a primary.
        t.attributes = crate::types::ObjectAttributes::new(0x0003_0470).unwrap();
        assert_eq!(validate_template(&t, 0, None), Err(Fmt1::Attributes));
        // A restricted decryption key without a symmetric algorithm.
        let mut t = kernel_template();
        if let PublicKind::Ecc(e) = &mut t.kind {
            e.parms.symmetric = SymDefObject::Null(());
        }
        assert_eq!(validate_template(&t, 0, None), Err(Fmt1::Symmetric));
        // Caller data for an asymmetric key.
        let mut t = kernel_template();
        t.attributes = crate::types::ObjectAttributes::new(0x0003_0452).unwrap();
        assert_eq!(validate_template(&t, 4, None), Err(Fmt1::Attributes));
    }
}
