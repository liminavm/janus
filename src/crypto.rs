// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cryptographic primitives the specification composes: HMAC, the two KDFs of Part 1
//! §11.4.10, AES-128 in CFB mode, P-256 and RSA-2048 key derivation, their signing and
//! decryption, and the deterministic generator primary keys are drawn from.
//!
//! **Derivation is part of the persistent format.** A primary key is not stored: it is derived
//! again from its hierarchy's seed every time `TPM2_CreatePrimary` runs, and anything sealed to
//! it is lost if the derivation ever changes. So the generator and every candidate loop here
//! are janus's own, built only on primitives whose output a standard fixes (SHA-256, HMAC,
//! AES); no library's key-generation routine sits between a seed and a key.

use crate::alg::Hash;
use aes::cipher::KeyIvInit;
use hmac::{KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// `HMAC(key, parts...)`.
pub fn hmac(hash: Hash, key: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    match hash {
        Hash::Sha256 => {
            let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
                .expect("HMAC takes a key of any length");
            for p in parts {
                m.update(p);
            }
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        }
    }
}

/// Whether two byte strings are equal, in time that depends only on their lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A KDF label: the string and its terminating zero, which the specification includes in the
/// derivation whether or not the caller's string carried one.
fn label_bytes(label: &[u8]) -> impl Iterator<Item = &[u8]> {
    let terminated = label.last() == Some(&0);
    [label, if terminated { &[][..] } else { &[0][..] }].into_iter()
}

/// The number of bytes `bits` occupies, and the mask for the first byte when `bits` is not a
/// whole number of bytes (the specification keeps the low-order bits).
fn byte_len(bits: u32) -> (usize, u8) {
    let len = bits.div_ceil(8) as usize;
    let rem = bits % 8;
    (len, if rem == 0 { 0xFF } else { (1u8 << rem) - 1 })
}

/// `KDFa` (SP 800-108 counter mode with HMAC): `bits` bits of key from `key`, keyed by `label`
/// and the two contexts.
pub fn kdfa(
    hash: Hash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Zeroizing<Vec<u8>> {
    let (len, mask) = byte_len(bits);
    let mut out = Zeroizing::new(Vec::with_capacity(len + hash.size()));
    let mut counter: u32 = 0;
    while out.len() < len {
        counter += 1;
        let c = counter.to_be_bytes();
        let b = bits.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&c];
        parts.extend(label_bytes(label));
        parts.extend([context_u, context_v, &b[..]]);
        out.extend_from_slice(&hmac(hash, key, &parts));
    }
    out.truncate(len);
    if let Some(first) = out.first_mut() {
        *first &= mask;
    }
    out
}

/// `KDFe` (SP 800-56A concatenation KDF): `bits` bits of key from the shared secret `z`.
pub fn kdfe(
    hash: Hash,
    z: &[u8],
    label: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    bits: u32,
) -> Zeroizing<Vec<u8>> {
    let (len, mask) = byte_len(bits);
    let mut out = Zeroizing::new(Vec::with_capacity(len + hash.size()));
    let mut counter: u32 = 0;
    while out.len() < len {
        counter += 1;
        let c = counter.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&c, z];
        parts.extend(label_bytes(label));
        parts.extend([party_u, party_v]);
        let mut d = hash.digest(&parts);
        out.extend_from_slice(d.as_slice());
        d.zeroize();
    }
    out.truncate(len);
    if let Some(first) = out.first_mut() {
        *first &= mask;
    }
    out
}

/// AES-128 in CFB mode, in place, over a buffer of any length.
pub fn aes128_cfb_encrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    cfb_mode::Encryptor::<aes::Aes128>::new(key.into(), iv.into()).encrypt(buf);
}

pub fn aes128_cfb_decrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into()).decrypt(buf);
}

/// A deterministic bit generator: the KDFa stream of one key and context. Primary keys are
/// drawn from one, so the same seed, template and data always give the same key.
pub struct Drbg {
    key: Zeroizing<Vec<u8>>,
    context: Vec<u8>,
    counter: u32,
    pending: Zeroizing<Vec<u8>>,
}

impl Drbg {
    const LABEL: &'static [u8] = b"janus DRBG";

    /// The generator for `seed`, under `label`, for one `context`.
    pub fn new(seed: &[u8], label: &[u8], context: &[&[u8]]) -> Drbg {
        let joined: Vec<u8> = context.concat();
        let key = kdfa(Hash::Sha256, seed, label, &joined, &[], 256);
        Drbg { key, context: joined, counter: 0, pending: Zeroizing::new(Vec::new()) }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut at = 0;
        while at < out.len() {
            if self.pending.is_empty() {
                self.counter = self.counter.checked_add(1).expect("a generator ran 2^32 blocks");
                let block = hmac(
                    Hash::Sha256,
                    &self.key,
                    &[&self.counter.to_be_bytes(), Self::LABEL, &[0], &self.context],
                );
                self.pending.extend_from_slice(&block);
            }
            let n = (out.len() - at).min(self.pending.len());
            out[at..at + n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            at += n;
        }
    }
}

/// A P-256 private key.
pub struct EccPrivate(p256::SecretKey);

impl EccPrivate {
    /// Draws a scalar from `drbg` by rejection: 32 bytes at a time until they encode an
    /// integer in `[1, n-1]`. The loop is janus's, not a library's, so it cannot change under
    /// an upgrade.
    pub fn generate(drbg: &mut Drbg) -> EccPrivate {
        loop {
            let mut candidate = Zeroizing::new([0u8; 32]);
            drbg.fill(&mut candidate[..]);
            if let Ok(k) = p256::SecretKey::from_slice(&candidate[..]) {
                return EccPrivate(k);
            }
        }
    }

    /// From stored scalar bytes; `None` unless they encode a scalar in `[1, n-1]`.
    pub fn from_bytes(b: &[u8]) -> Option<EccPrivate> {
        (b.len() == 32).then(|| p256::SecretKey::from_slice(b).ok().map(EccPrivate)).flatten()
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().into())
    }

    /// The public point's coordinates.
    pub fn public(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.0.public_key().to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().expect("an uncompressed point has x"));
        y.copy_from_slice(point.y().expect("an uncompressed point has y"));
        (x, y)
    }

    /// An ECDSA signature `(r, s)` over a 32-byte digest, its nonce derived as RFC 6979
    /// derives it.
    pub fn sign(&self, digest: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let key = p256::ecdsa::SigningKey::from(&self.0);
        let sig: p256::ecdsa::Signature =
            key.sign_prehash(digest).expect("a 32-byte digest signs under P-256");
        let (r, s) = sig.split_bytes();
        (r.into(), s.into())
    }

    /// The x coordinate of `self × peer`, the ECDH shared secret `Z`.
    pub fn ecdh(&self, peer: &EccPublicKey) -> Zeroizing<[u8; 32]> {
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.0.as_affine());
        Zeroizing::new((*shared.raw_secret_bytes()).into())
    }
}

/// The public exponent a template's zero stands for (`RSA_DEFAULT_PUBLIC_EXPONENT`).
pub const RSA_DEFAULT_EXPONENT: u32 = 65537;
/// An RSA-2048 modulus, in bytes.
pub const RSA_MODULUS_BYTES: usize = 256;
/// One of its primes, in bytes: what an RSA object's sensitive area holds.
pub const RSA_PRIME_BYTES: usize = RSA_MODULUS_BYTES / 2;

/// The exponent a template's `exponent` field asks for (`CryptRsaGenerateKey`): zero is the
/// default; anything else must be a prime of at least 65537, or `None` (`TPM_RC_RANGE`).
pub fn rsa_exponent(e: u32) -> Option<u32> {
    if e == 0 {
        return Some(RSA_DEFAULT_EXPONENT);
    }
    let prime = (2..).take_while(|d: &u32| d.saturating_mul(*d) <= e).all(|d| !e.is_multiple_of(d));
    (e >= RSA_DEFAULT_EXPONENT && prime).then_some(e)
}

/// Small odd primes a candidate is divided by before the primality test runs; they reject
/// most composites for a fraction of its cost, and cannot change which candidate is accepted.
const SMALL_PRIMES: [u32; 53] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// `n mod m`, `n` big-endian. In 64 bits, since `m` may be an exponent close to 2^32.
fn rem_small(n: &[u8], m: u32) -> u32 {
    let m = u64::from(m);
    n.iter().fold(0, |r, b| (r * 256 + u64::from(*b)) % m) as u32
}

/// An RSA-2048 private key.
pub struct RsaPrivate(rsa::RsaPrivateKey);

impl RsaPrivate {
    /// Draws a key from `drbg` (`CryptRsaGenerateKey`, with janus's own candidate loop): each
    /// prime is 128 bytes from the generator with the top two bits set, so the modulus has
    /// exactly 2048 bits, and the low bit set. A candidate `p` is kept if `gcd(e, p - 1) = 1`
    /// (`e` is prime, so: `p mod e != 1`) and it is prime; otherwise the next 128 bytes are
    /// drawn. `q` likewise, and drawn again while `|p - q| < 2^100`. Every step is a function
    /// of the generator's output and of facts about numbers, so a seed always gives one key.
    pub fn generate(drbg: &mut Drbg, e: u32) -> RsaPrivate {
        let p = rsa_prime(drbg, e);
        loop {
            let q = rsa_prime(drbg, e);
            let differ = if p > q { &p - &q } else { &q - &p };
            if differ.bits() <= 100 {
                continue;
            }
            let key =
                rsa::RsaPrivateKey::from_p_q(p.clone(), q, rsa::BoxedUint::from(u64::from(e)))
                    .expect("two distinct primes, each coprime to e minus one, make a key");
            return RsaPrivate(key);
        }
    }

    /// From a modulus and the prime an object's sensitive area holds
    /// (`CryptRsaLoadPrivateExponent`): `None` (`TPM_RC_BINDING`) unless the prime divides the
    /// modulus and the two make a key for `e`.
    pub fn from_prime(n: &[u8], e: u32, p: &[u8]) -> Option<RsaPrivate> {
        if n.len() != RSA_MODULUS_BYTES || p.len() != RSA_PRIME_BYTES {
            return None;
        }
        let n = rsa::BoxedUint::from_be_slice(n, 2048).ok()?;
        let p = rsa::BoxedUint::from_be_slice(p, 1024).ok()?;
        let divisor = crypto_bigint::NonZero::new(p.clone()).into_option()?;
        let (q, r) = n.div_rem(&divisor);
        if !bool::from(r.is_zero()) {
            return None;
        }
        if q.bits() > 1024 {
            return None;
        }
        let q_bytes = Zeroizing::new(q.to_be_bytes());
        let q = rsa::BoxedUint::from_be_slice(&q_bytes[q_bytes.len() - RSA_PRIME_BYTES..], 1024)
            .ok()?;
        rsa::RsaPrivateKey::from_p_q(p, q, rsa::BoxedUint::from(u64::from(e))).ok().map(RsaPrivate)
    }

    /// The modulus, 256 bytes.
    pub fn modulus(&self) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let n = self.0.n().as_ref().to_be_bytes();
        n[n.len() - RSA_MODULUS_BYTES..].to_vec()
    }

    /// The first prime, 128 bytes: what the sensitive area stores.
    pub fn prime(&self) -> Zeroizing<Vec<u8>> {
        use rsa::traits::PrivateKeyParts;
        let p = self.0.primes()[0].to_be_bytes();
        Zeroizing::new(p[p.len() - RSA_PRIME_BYTES..].to_vec())
    }

    /// RSA decryption under `scheme`, blinded with `rng`. A ciphertext that is not smaller
    /// than the modulus is [`RsaDecryptError::Size`]; one that does not decode,
    /// [`RsaDecryptError::Value`].
    pub fn decrypt(
        &self,
        rng: &mut impl rand_core::CryptoRng,
        scheme: RsaDecrypt<'_>,
        c: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RsaDecryptError> {
        if c.len() != RSA_MODULUS_BYTES {
            return Err(RsaDecryptError::Size);
        }
        if c >= self.modulus().as_slice() {
            return Err(RsaDecryptError::Size);
        }
        let m = match scheme {
            RsaDecrypt::Raw => {
                let c =
                    rsa::BoxedUint::from_be_slice(c, 2048).map_err(|_| RsaDecryptError::Size)?;
                let m = rsa::hazmat::rsa_decrypt_and_check(&self.0, Some(rng), &c)
                    .map_err(|_| RsaDecryptError::Value)?;
                let m = m.to_be_bytes();
                m[m.len() - RSA_MODULUS_BYTES..].to_vec()
            }
            RsaDecrypt::Pkcs1 => self
                .0
                .decrypt_blinded(rng, rsa::Pkcs1v15Encrypt, c)
                .map_err(|_| RsaDecryptError::Value)?,
            RsaDecrypt::Oaep(label) => {
                let padding = if label.is_empty() {
                    rsa::Oaep::<sha2::Sha256>::new()
                } else {
                    rsa::Oaep::<sha2::Sha256>::new_with_label(label)
                };
                self.0.decrypt_blinded(rng, padding, c).map_err(|_| RsaDecryptError::Value)?
            }
        };
        Ok(Zeroizing::new(m))
    }

    /// An RSASSA-PKCS1-v1_5 (`pss` false) or RSASSA-PSS signature over a SHA-256 digest, the
    /// PSS salt as long as the digest (`CryptRsaPssSaltSize`).
    /// `None` for a digest that is not a SHA-256 digest's size.
    pub fn sign(
        &self,
        rng: &mut impl rand_core::CryptoRng,
        pss: bool,
        digest: &[u8],
    ) -> Option<Vec<u8>> {
        let sig = if pss {
            self.0.sign_with_rng(rng, rsa::Pss::<sha2::Sha256>::new(), digest)
        } else {
            self.0.sign_with_rng(rng, rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), digest)
        };
        sig.ok()
    }
}

fn rsa_prime(drbg: &mut Drbg, e: u32) -> rsa::BoxedUint {
    loop {
        let mut b = Zeroizing::new([0u8; RSA_PRIME_BYTES]);
        drbg.fill(&mut b[..]);
        b[0] |= 0xC0;
        b[RSA_PRIME_BYTES - 1] |= 1;
        if rem_small(&b[..], e) == 1 || SMALL_PRIMES.iter().any(|m| rem_small(&b[..], *m) == 0) {
            continue;
        }
        let candidate = rsa::BoxedUint::from_be_slice(&b[..], 1024).expect("128 bytes fit");
        if crypto_primes::is_prime(crypto_primes::Flavor::Any, &candidate) {
            return candidate;
        }
    }
}

/// How an RSA ciphertext is padded (`TPMT_RSA_DECRYPT`).
pub enum RsaDecrypt<'a> {
    /// `TPM_ALG_NULL`: the bare RSA operation.
    Raw,
    /// `TPM_ALG_RSAES`.
    Pkcs1,
    /// `TPM_ALG_OAEP` with SHA-256 and this label, its terminating NUL included.
    Oaep(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RsaDecryptError {
    Size,
    Value,
}

/// The platform's randomness, as the RNG the RSA and ECDSA code wants for blinding and salts.
/// It wraps the platform, not a [`Drbg`], so a fresh value can never come from a generator
/// that would repeat it.
pub struct PlatformRng<'a, P: crate::Platform>(pub &'a mut P);

impl<P: crate::Platform> rand_core::TryRng for PlatformRng<'_, P> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.0.fill_random(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.0.fill_random(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_random(dst);
        Ok(())
    }
}

impl<P: crate::Platform> rand_core::TryCryptoRng for PlatformRng<'_, P> {}

/// A P-256 point that is on the curve and not the identity.
pub struct EccPublicKey(p256::PublicKey);

impl EccPublicKey {
    /// `None` for coordinates longer than 32 bytes or not a point on the curve
    /// (`TPM_RC_ECC_POINT` to the caller).
    pub fn from_coordinates(x: &[u8], y: &[u8]) -> Option<EccPublicKey> {
        if x.len() > 32 || y.len() > 32 {
            return None;
        }
        // A coordinate may arrive without its leading zero bytes.
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[33 - x.len()..33].copy_from_slice(x);
        sec1[65 - y.len()..].copy_from_slice(y);
        p256::PublicKey::from_sec1_bytes(&sec1).ok().map(EccPublicKey)
    }
}

/// `TPMS_ALGORITHM_DETAIL_ECC` for a curve (`CryptEccGetParameters`): the field and curve
/// constants as the reference writes them, `p`, `gX` and `gY` padded to the key size and the
/// rest in their shortest form. NIST P-256's KDF is KDF1 (SP 800-56A) over SHA-256, and it names
/// no signing scheme.
/// `TPM_ALG_KDF1_SP800_56A`.
const KDF1_SP800_56A: u16 = 0x0020;

pub fn ecc_parameters(curve: crate::types::EccCurve, out: &mut crate::wire::Writer) {
    const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    const A: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
    const B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
    const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let crate::types::EccCurve::NistP256 = curve;
    out.u16(crate::alg::curve::NIST_P256);
    out.u16(256);
    out.u16(KDF1_SP800_56A);
    out.u16(crate::alg::id::SHA256);
    out.u16(crate::alg::id::NULL);
    for c in [P, A, B, GX, GY, N] {
        let bytes: Vec<u8> = (0..c.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&c[i..i + 2], 16).expect("a hex constant"))
            .collect();
        out.tpm2b(&bytes);
    }
    out.tpm2b(&[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RSA key's derivation is part of the persistent format (see the module comment):
    /// this seed must always give this modulus, or every RSA primary key moves.
    #[test]
    fn rsa_derivation_is_pinned() {
        let mut drbg = Drbg::new(&[7; 32], b"probe", &[]);
        let k = RsaPrivate::generate(&mut drbg, RSA_DEFAULT_EXPONENT);
        let pinned = "ba38fbdef582c8b4132e8b75340adc9507cd70d772259fdda9c05011593aad13f589fedd0f27027892f448f8\
         11c4267bd624226190d1fb2093ff49524b1f7810eaffaeac7824ca0d0bb58529feb27c947b54927337b8a952\
         3fdfcfa97cd6ed643f152f23ed563785fb06dfcdc687256aab26afdcd294c92bfd8e11f01e6823cec0cbd5ec\
         813a8ca53a5f6acbc83677b8744fbd62277ad363eb57434f1bafda8a2f581a7cbd1605f20f39eb2fbe2ce8eb\
         bf7b33632e7b9326b56590a9e26a8fab5e10d0aa43dcba07c62d8c12494c658514c35e3f73609f6109847c96\
         32d9dd891aee7d465e4574b208985b8219dbf03f9614e6ec8dc8733d574f0ea6ab284a7b";
        assert_eq!(k.modulus(), hex(pinned));
        // The stored prime brings the key back, and a prime that does not divide the modulus
        // does not.
        let again = RsaPrivate::from_prime(&k.modulus(), RSA_DEFAULT_EXPONENT, &k.prime()).unwrap();
        assert_eq!(again.modulus(), k.modulus());
        let mut wrong = k.prime().to_vec();
        wrong[127] ^= 2;
        assert!(RsaPrivate::from_prime(&k.modulus(), RSA_DEFAULT_EXPONENT, &wrong).is_none());
    }

    #[test]
    fn rsa_exponents_are_zero_or_primes_from_65537() {
        assert_eq!(rsa_exponent(0), Some(65537));
        assert_eq!(rsa_exponent(65537), Some(65537));
        assert_eq!(rsa_exponent(65539), Some(65539));
        for e in [3, 17, 65535, 65541, 0xFFFF_FFFF] {
            assert_eq!(rsa_exponent(e), None, "{e}");
        }
    }

    /// The candidate test divides by the exponent too, which may be any prime up to
    /// 2^32 - 5: a remainder times 256 must not overflow.
    #[test]
    fn a_candidates_remainder_is_exact_for_the_largest_exponent() {
        let e = 0xFFFF_FFFB;
        assert_eq!(rsa_exponent(e), Some(e));
        let n = [0xFFu8; 128];
        let expected = n.iter().fold(0u128, |r, b| (r * 256 + u128::from(*b)) % u128::from(e));
        assert_eq!(u128::from(rem_small(&n, e)), expected);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The SHA-256 known answer the TCG reference's self-test checks KDFa against
    /// (`KdfTestData.h`, `TestKDFa` in `AlgorithmTests.c`).
    #[test]
    fn kdfa_matches_the_reference_self_test() {
        let key = hex("271fa08bbdc5060ec3dfa928ff9b73123a12da0c");
        let out = kdfa(
            Hash::Sha256,
            &key,
            b"KDFSELFTESTLABEL\0",
            &hex("ce244f395dca7391"),
            &hex("da504031ddf12e83"),
            160,
        );
        assert_eq!(&out[..], &hex("bb0259e1c8ba607e6a2cd704b69a902e9ade84c4")[..]);
    }

    #[test]
    fn kdfa_matches_an_independent_computation() {
        // KDFa(SHA256, key, "TEST", "U", "V", 384): two HMAC blocks, truncated.
        let key = b"key";
        let out = kdfa(Hash::Sha256, key, b"TEST", b"U", b"V", 384);
        let b1 = hmac(
            Hash::Sha256,
            key,
            &[&1u32.to_be_bytes(), b"TEST\0", b"U", b"V", &384u32.to_be_bytes()],
        );
        let b2 = hmac(
            Hash::Sha256,
            key,
            &[&2u32.to_be_bytes(), b"TEST\0", b"U", b"V", &384u32.to_be_bytes()],
        );
        assert_eq!(&out[..32], &b1[..]);
        assert_eq!(&out[32..], &b2[..16]);
        // A label that already ends in zero gets no second one.
        assert_eq!(kdfa(Hash::Sha256, key, b"TEST\0", b"U", b"V", 384), out);
        // A bit count that is not a whole number of bytes keeps the low-order bits.
        let odd = kdfa(Hash::Sha256, key, b"TEST", b"U", b"V", 12);
        assert_eq!(odd.len(), 2);
        assert_eq!(odd[0] & 0xF0, 0);
    }

    /// KDFe is SP 800-56C's one-step KDF with the label, terminator and party infos as its
    /// fixed info; OpenSSL implements that independently (`openssl kdf -keylen 48 -kdfopt
    /// digest:SHA256 -kdfopt hexsecret:00..1f -kdfopt hexinfo:<"IDENTITY\0" U*32 V*32>
    /// SSKDF`).
    #[test]
    fn kdfe_matches_openssl_sskdf() {
        let z: Vec<u8> = (0..32).collect();
        let out = kdfe(Hash::Sha256, &z, b"IDENTITY", &[b'U'; 32], &[b'V'; 32], 384);
        assert_eq!(
            &out[..],
            &hex(concat!(
                "09aa3a8dc35d7297794947d0d4713066a6a2de2fc53a4254433638d29b70133f",
                "50abbdb05d241458b8b2ce0350f83d98"
            ))[..]
        );
    }

    #[test]
    fn aes128_cfb_matches_a_published_vector() {
        // NIST SP 800-38A F.3.13 (CFB128-AES128.Encrypt), first two blocks.
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let mut buf = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        aes128_cfb_encrypt(&key, &iv, &mut buf);
        assert_eq!(buf, hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"));
        aes128_cfb_decrypt(&key, &iv, &mut buf);
        assert_eq!(buf, hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"));
    }

    #[test]
    fn a_generator_is_a_pure_function_of_its_inputs() {
        let mut a = Drbg::new(b"seed", b"label", &[b"ctx"]);
        let mut b = Drbg::new(b"seed", b"label", &[b"ctx"]);
        let mut x = [0u8; 70];
        let mut y = [0u8; 70];
        a.fill(&mut x[..10]);
        a.fill(&mut x[10..]);
        b.fill(&mut y);
        assert_eq!(x, y);
        let mut c = Drbg::new(b"seed", b"label", &[b"ctx2"]);
        let mut z = [0u8; 70];
        c.fill(&mut z);
        assert_ne!(x, z);
    }

    /// The pinned derivation: a change to the generator or the rejection loop changes this key,
    /// and every primary key with it. If this fails, the change breaks every sealed secret.
    #[test]
    fn primary_ecc_derivation_is_pinned() {
        let mut d = Drbg::new(&[7u8; 32], b"janus test", &[b"context"]);
        let k = EccPrivate::generate(&mut d);
        let (x, _) = k.public();
        assert_eq!(x.to_vec(), PINNED_X.to_vec(), "{:02x?}", x);
    }

    const PINNED_X: [u8; 32] = [
        0x15, 0xd1, 0x16, 0x44, 0x52, 0xf7, 0xbf, 0xaa, 0x13, 0x78, 0xf6, 0x09, 0x23, 0xa9, 0x86,
        0xcc, 0xd8, 0x55, 0xf1, 0x44, 0x87, 0xe1, 0x4a, 0x2f, 0x3f, 0xe0, 0xea, 0xab, 0x85, 0x0c,
        0xfa, 0xb5,
    ];

    #[test]
    fn ecdh_agrees_from_both_sides() {
        let a = EccPrivate::generate(&mut Drbg::new(b"a", b"t", &[]));
        let b = EccPrivate::generate(&mut Drbg::new(b"b", b"t", &[]));
        let (ax, ay) = a.public();
        let (bx, by) = b.public();
        let pa = EccPublicKey::from_coordinates(&ax, &ay).unwrap();
        let pb = EccPublicKey::from_coordinates(&bx, &by).unwrap();
        assert_eq!(*a.ecdh(&pb), *b.ecdh(&pa));
        // Not on the curve.
        let mut bad = ay;
        bad[31] ^= 1;
        assert!(EccPublicKey::from_coordinates(&ax, &bad).is_none());
    }
}
