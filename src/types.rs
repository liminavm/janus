// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TPM 2.0 structures janus reads and writes (Part 2), described once each through the
//! marshalling generator.
//!
//! Only what the implemented algorithms need is representable: AES-128 in CFB mode, ECC on
//! NIST P-256, RSA 2048, keyed-hash objects, and SHA-256. A selector outside that set is the
//! response code the reference returns for it, at the point the reference returns it.

use crate::alg::{Hash, MAX_DIGEST, curve, id};
use crate::marshal::{List, Marshal, Unmarshal};
use crate::pcr::Selection;
use crate::rc::Fmt1;
use crate::wire::{Buf, Reader, Writer};
use zeroize::Zeroize;

/// Largest ECC coordinate or scalar (P-256).
pub const MAX_ECC_KEY_BYTES: usize = 32;
/// Largest RSA modulus (2048 bits).
pub const MAX_RSA_KEY_BYTES: usize = 256;
/// Largest sealed data object (`MAX_SYM_DATA`).
pub const MAX_SYM_DATA: usize = 128;
/// A `TPMT_HA`: algorithm and digest, the largest a name or `TPM2B_DATA` can be.
pub const MAX_NAME: usize = 2 + MAX_DIGEST;

/// `TPM2B_DIGEST`, `TPM2B_NONCE`: at most one digest.
pub type Digest2b = Buf<MAX_DIGEST>;
/// `TPM2B_ECC_PARAMETER`.
pub type EccParameter = Buf<MAX_ECC_KEY_BYTES>;
/// `TPM2B_NAME`.
pub type Name2b = Buf<MAX_NAME>;
/// `TPM2B_DATA`.
pub type Data2b = Buf<MAX_NAME>;

/// A `TPM2B` holding secret bytes: zeroized on drop, no `Debug`, no `Clone`.
pub struct Secret<const MAX: usize>(Buf<MAX>);

impl<const MAX: usize> Secret<MAX> {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// `None` when `b` is longer than `MAX`.
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Buf::from_slice(b).map(Secret)
    }

    pub const fn empty() -> Self {
        Secret(Buf::empty())
    }
}

impl<const MAX: usize> Drop for Secret<MAX> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const MAX: usize> Marshal for Secret<MAX> {
    fn write(&self, w: &mut Writer) {
        self.0.write(w);
    }
}

impl<const MAX: usize> Unmarshal for Secret<MAX> {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(Secret(Buf::read(r)?))
    }
}

wire_values! {
    /// `TPMI_AES_KEY_BITS`.
    pub enum AesKeyBits: u16 [Fmt1::Value] {
        Bits128 = 128,
    }
}

wire_values! {
    /// `TPMI_ALG_SYM_MODE`.
    pub enum SymMode: u16 [Fmt1::Mode] {
        Cfb = id::CFB,
    }
}

wire_struct! {
    /// The AES arm of `TPMT_SYM_DEF(_OBJECT)`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AesDef {
        pub key_bits: AesKeyBits,
        pub mode: SymMode,
    }
}

wire_union! {
    /// `TPMT_SYM_DEF_OBJECT+`: the symmetric algorithm a storage key protects its children
    /// with, or none.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SymDefObject: u16 [Fmt1::Symmetric] {
        Null = id::NULL => (),
        Aes = id::AES => AesDef,
    }
}

wire_union! {
    /// `TPMT_SYM_DEF_OBJECT` where NULL is not allowed (a symmetric cipher object).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SymObject: u16 [Fmt1::Symmetric] {
        Aes = id::AES => AesDef,
    }
}

wire_union! {
    /// `TPMT_SYM_DEF+`: a session's parameter encryption algorithm, or none.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SymDef: u16 [Fmt1::Symmetric] {
        Null = id::NULL => (),
        Aes = id::AES => AesDef,
    }
}

wire_union! {
    /// `TPMT_ECC_SCHEME+`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EccScheme: u16 [Fmt1::Scheme] {
        Null = id::NULL => (),
        Ecdsa = id::ECDSA => Hash,
        Ecdh = id::ECDH => Hash,
    }
}

wire_union! {
    /// `TPMT_KDF_SCHEME+`. No KDF scheme is implemented.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KdfScheme: u16 [Fmt1::Kdf] {
        Null = id::NULL => (),
    }
}

wire_values! {
    /// `TPMI_ECC_CURVE`.
    pub enum EccCurve: u16 [Fmt1::Curve] {
        NistP256 = curve::NIST_P256,
    }
}

wire_struct! {
    /// `TPMS_ECC_PARMS`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EccParms {
        pub symmetric: SymDefObject,
        pub scheme: EccScheme,
        pub curve: EccCurve,
        pub kdf: KdfScheme,
    }
}

wire_union! {
    /// `TPMT_RSA_SCHEME+`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RsaScheme: u16 [Fmt1::Value] {
        Null = id::NULL => (),
        Rsassa = id::RSASSA => Hash,
        Rsaes = id::RSAES => (),
        Rsapss = id::RSAPSS => Hash,
        Oaep = id::OAEP => Hash,
    }
}

wire_values! {
    /// `TPMI_RSA_KEY_BITS`.
    pub enum RsaKeyBits: u16 [Fmt1::Value] {
        Bits2048 = 2048,
    }
}

wire_struct! {
    /// `TPMS_RSA_PARMS`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RsaParms {
        pub symmetric: SymDefObject,
        pub scheme: RsaScheme,
        pub key_bits: RsaKeyBits,
        /// Zero means the default, 65537.
        pub exponent: u32,
    }
}

wire_union! {
    /// `TPMT_KEYEDHASH_SCHEME+`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KeyedHashScheme: u16 [Fmt1::Value] {
        Null = id::NULL => (),
        Hmac = id::HMAC => Hash,
    }
}

wire_struct! {
    /// `TPMS_ECC_POINT`.
    #[derive(Clone, Debug)]
    pub struct EccPoint {
        pub x: EccParameter,
        pub y: EccParameter,
    }
}

wire_struct! {
    /// The ECC arm of `TPMT_PUBLIC`: `TPMS_ECC_PARMS` and the public point.
    #[derive(Clone, Debug)]
    pub struct EccPublic {
        pub parms: EccParms,
        pub unique: EccPoint,
    }
}

wire_struct! {
    /// The RSA arm of `TPMT_PUBLIC`: `TPMS_RSA_PARMS` and the modulus.
    #[derive(Clone, Debug)]
    pub struct RsaPublic {
        pub parms: RsaParms,
        pub unique: Buf<MAX_RSA_KEY_BYTES>,
    }
}

wire_struct! {
    /// The keyed-hash arm of `TPMT_PUBLIC`: the scheme and the unique digest.
    #[derive(Clone, Debug)]
    pub struct KeyedHashPublic {
        pub scheme: KeyedHashScheme,
        pub unique: Digest2b,
    }
}

wire_struct! {
    /// The symmetric-cipher arm of `TPMT_PUBLIC`.
    #[derive(Clone, Debug)]
    pub struct SymCipherPublic {
        pub sym: SymObject,
        pub unique: Digest2b,
    }
}

wire_union! {
    /// `TPMT_PUBLIC_PARMS`: an object type's parameters without a key, as `TPM2_TestParms`
    /// asks about them.
    #[derive(Clone, Copy, Debug)]
    pub enum PublicParms: u16 [Fmt1::Type] {
        Rsa = id::RSA => RsaParms,
        KeyedHash = id::KEYEDHASH => KeyedHashScheme,
        Ecc = id::ECC => EccParms,
        SymCipher = id::SYMCIPHER => SymObject,
    }
}

wire_union! {
    /// `TPMI_ALG_PUBLIC` with the `TPMU_PUBLIC_PARMS` and `TPMU_PUBLIC_ID` it selects.
    #[derive(Clone, Debug)]
    pub enum PublicKind: u16 [Fmt1::Type] {
        Rsa = id::RSA => RsaPublic,
        KeyedHash = id::KEYEDHASH => KeyedHashPublic,
        Ecc = id::ECC => EccPublic,
        SymCipher = id::SYMCIPHER => SymCipherPublic,
    }
}

wire_bits! {
    /// `TPMA_OBJECT`. Bits 8 and 9 (firmware- and SVN-limited objects) are not implemented and
    /// count as reserved.
    pub struct ObjectAttributes(u32) reserved 0xFFF0_F309; {
        fixed_tpm = 1,
        st_clear = 2,
        fixed_parent = 4,
        sensitive_data_origin = 5,
        user_with_auth = 6,
        admin_with_policy = 7,
        no_da = 10,
        encrypted_duplication = 11,
        restricted = 16,
        decrypt = 17,
        sign_encrypt = 18,
        x509sign = 19,
    }
}

/// `TPMT_PUBLIC`. Its type selects both the parameters and the unique field, which are
/// separated from it by three common fields, so the selector is written first and the body
/// last.
#[derive(Clone, Debug)]
pub struct Public {
    pub name_alg: Hash,
    pub attributes: ObjectAttributes,
    pub auth_policy: Digest2b,
    pub kind: PublicKind,
}

impl Marshal for Public {
    fn write(&self, w: &mut Writer) {
        self.kind.selector().write(w);
        self.name_alg.write(w);
        self.attributes.write(w);
        self.auth_policy.write(w);
        self.kind.write_body(w);
    }
}

impl Unmarshal for Public {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let selector = u16::read(r)?;
        if !PublicKind::is_selector(selector) {
            return Err(Fmt1::Type);
        }
        let name_alg = Hash::read(r)?;
        let attributes = ObjectAttributes::read(r)?;
        let auth_policy = Digest2b::read(r)?;
        let kind = PublicKind::read_body(selector, r)?;
        Ok(Public { name_alg, attributes, auth_policy, kind })
    }
}

impl Public {
    /// The object's name: its name algorithm, then the digest of its marshalled public area.
    /// It is computed, never stored, so it cannot disagree with the area it names.
    pub fn name(&self) -> Name2b {
        let mut area = Writer::new();
        self.write(&mut area);
        let digest = self.name_alg.digest(&[&area.into_vec()]);
        let mut w = Writer::new();
        self.name_alg.write(&mut w);
        w.bytes(digest.as_slice());
        Name2b::from_slice(&w.into_vec()).expect("a name is at most a TPMT_HA")
    }
}

wire_struct! {
    /// `TPMS_SENSITIVE_CREATE`: the authorization value and data the caller gives a new object.
    pub struct SensitiveCreate {
        pub user_auth: Secret<MAX_DIGEST>,
        pub data: Secret<MAX_SYM_DATA>,
    }
}

wire_struct! {
    /// `TPMS_CREATION_DATA`.
    #[derive(Debug)]
    pub struct CreationData {
        pub pcr_select: List<Selection, 1>,
        pub pcr_digest: Digest2b,
        /// `TPMA_LOCALITY` of the creating command.
        pub locality: u8,
        /// `TPM_ALG_ID` of the parent's name: `TPM_ALG_NULL` for a primary.
        pub parent_name_alg: u16,
        pub parent_name: Name2b,
        pub parent_qualified_name: Name2b,
        pub outside_info: Data2b,
    }
}

wire_struct! {
    /// `TPMT_TK_CREATION`.
    #[derive(Debug)]
    pub struct TkCreation {
        /// `TPM_ST_CREATION`.
        pub tag: u16,
        pub hierarchy: u32,
        pub digest: Digest2b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{read_prefix, round_trips};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The kernel's null-hierarchy primary template, from `boot.jsonl`: an ECC P-256
    /// restricted decryption key protecting its children with AES-128-CFB.
    const KERNEL_TEMPLATE: &str = "0023000b00030472000000060080004300100003001000000000";

    #[test]
    fn the_kernels_primary_template_reads_and_writes_back() {
        let bytes = hex(KERNEL_TEMPLATE);
        let (p, n) = read_prefix::<Public>(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(p.name_alg, Hash::Sha256);
        assert!(
            p.attributes.restricted() && p.attributes.decrypt() && !p.attributes.sign_encrypt()
        );
        match &p.kind {
            PublicKind::Ecc(e) => {
                assert_eq!(e.parms.curve, EccCurve::NistP256);
                assert_eq!(
                    e.parms.symmetric,
                    SymDefObject::Aes(AesDef { key_bits: AesKeyBits::Bits128, mode: SymMode::Cfb })
                );
                assert_eq!(e.parms.scheme, EccScheme::Null(()));
            }
            other => panic!("read {other:?}"),
        }
        assert!(round_trips::<Public>(&bytes));
    }

    #[test]
    fn swtpms_answer_to_the_kernel_names_the_area_it_returned() {
        // CreatePrimary's outPublic and name from swtpm's response in boot.jsonl.
        let public = hex(concat!(
            "0023000b00030472000000060080004300100003001000203141b27ac91f2c6a7c4d71b0f16cff",
            "963215b7b2573b452baa56719f45cc78b20020f55ce04903c915be47eb63210a300978aa625a5f",
            "0ab9ee6041adb108520572870037"
        ));
        let name = hex("000bbe3e7b66e145032d76965d0f10f7badf8ee729d58a9c8de04316180e890c65c7");
        let (p, _) = read_prefix::<Public>(&public).unwrap();
        assert_eq!(p.name().as_slice(), name.as_slice());
    }

    #[test]
    fn a_selector_is_rejected_before_the_fields_after_it() {
        // An unknown type, followed by an unknown hash: TPM_RC_TYPE, not TPM_RC_HASH.
        assert_eq!(read_prefix::<Public>(&hex("00990004")).unwrap_err(), Fmt1::Type);
        // A reserved attribute bit.
        assert_eq!(
            read_prefix::<Public>(&hex("0023000b00000001")).unwrap_err(),
            Fmt1::ReservedBits
        );
        // P-384, which is not implemented.
        let p384 = hex("0023000b0003047200000006008000430010000400100000000000");
        assert_eq!(read_prefix::<Public>(&p384).unwrap_err(), Fmt1::Curve);
        // AES-256.
        let aes256 = hex("0023000b0003047200000006010000430010000300100000000000");
        assert_eq!(read_prefix::<Public>(&aes256).unwrap_err(), Fmt1::Value);
    }
}
