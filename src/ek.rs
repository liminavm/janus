// SPDX-License-Identifier: MIT OR Apache-2.0

//! Endorsement key certificates, as a TPM's manufacturer provisions them.
//!
//! An EK is a primary key of the endorsement hierarchy made from a template the TCG fixes
//! ("TCG EK Credential Profile for TPM Family 2.0", §5.4), so the TPM can recreate it at any
//! time and a certificate issued for its public key stays valid. The certificate lives in a
//! platform-created NV index at the address the profile assigns (§2.2.2.5), with the attributes
//! the PC Client profile requires of a preprovisioned one (PTP §4.6.3.1). Clients such as
//! systemd-tpm2-setup look for it there, recreate the key from the template, and persist it
//! only when the two public keys agree.
//!
//! janus provides the key and holds the certificate; who issues it, and what it says, is the
//! host's.

use crate::marshal::Unmarshal;
use crate::nv::{NvAttributes, NvPublic};
use crate::types::{Digest2b, Public};
use crate::wire::Reader;

/// An EK profile janus can make the key for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EkProfile {
    /// Template H-2: an ECC NIST P-256 storage key, SHA-256 names, AES-128-CFB.
    EccNistP256,
}

/// Template H-2 as a marshalled `TPMT_PUBLIC`: ECC, SHA-256, fixedTPM | fixedParent |
/// sensitiveDataOrigin | userWithAuth | adminWithPolicy | restricted | decrypt, policy B, AES-128
/// CFB, no scheme, P-256, no KDF, and an empty unique point.
const TEMPLATE_H2: [u8; 58] = [
    0x00, 0x23, // TPM_ALG_ECC
    0x00, 0x0b, // TPM_ALG_SHA256
    0x00, 0x03, 0x00, 0xf2, // objectAttributes
    0x00,
    0x20, // authPolicy: PolicySecret(TPM_RH_ENDORSEMENT) OR PolicyAuthorizeNV(0x01C07F01)
    0xca, 0x3d, 0x0a, 0x99, 0xa2, 0xb9, 0x39, 0x06, 0xf7, 0xa3, 0x34, 0x24, 0x14, 0xef, 0xcf, 0xb3,
    0xa3, 0x85, 0xd4, 0x4c, 0xd1, 0xfd, 0x45, 0x90, 0x89, 0xd1, 0x9b, 0x50, 0x71, 0xc0, 0xb7, 0xa0,
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // symmetric: AES, 128, CFB
    0x00, 0x10, // scheme: TPM_ALG_NULL
    0x00, 0x03, // curveID: TPM_ECC_NIST_P256
    0x00, 0x10, // kdf: TPM_ALG_NULL
    0x00, 0x00, 0x00, 0x00, // unique: empty x, empty y
];

impl EkProfile {
    /// The NV index the profile's certificate is read from.
    pub const fn certificate_index(self) -> u32 {
        match self {
            EkProfile::EccNistP256 => 0x01C0_0014,
        }
    }

    /// The template the key is made from.
    pub(crate) fn template(self) -> Public {
        let bytes: &[u8] = match self {
            EkProfile::EccNistP256 => &TEMPLATE_H2,
        };
        let mut r = Reader::new(bytes);
        let public = Public::read(&mut r).expect("an EK template is a valid TPMT_PUBLIC");
        assert!(r.is_empty(), "an EK template is exactly one TPMT_PUBLIC");
        public
    }

    /// The certificate index's public area once written: platform-created, readable with its
    /// own (empty) authorization, the owner's or the platform's, exempt from dictionary-attack
    /// lockout, written by the platform alone and locked until it is undefined. None of the
    /// attributes the PC Client profile rules out (ownerWrite, authWrite, globalLock,
    /// clearStClear, orderly, readStClear) is set.
    pub(crate) fn certificate_public(self, size: u16) -> NvPublic {
        let attributes = NvAttributes::new(
            1 << 0 // ppWrite
                | 1 << 13 // writeDefine
                | 1 << 16 // ppRead
                | 1 << 17 // ownerRead
                | 1 << 18 // authRead
                | 1 << 25 // noDA
                | 1 << 30, // platformCreate
        )
        .expect("the EK certificate's attributes set no reserved bit");
        NvPublic {
            index: self.certificate_index(),
            name_alg: crate::alg::Hash::Sha256,
            attributes,
            auth_policy: Digest2b::empty(),
            data_size: size,
        }
    }
}

/// Why a certificate was not provisioned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionError {
    /// The profile's index is already defined: a certificate is never replaced in place.
    Defined,
    /// Empty, or larger than an index holds.
    Size,
    /// The TPM holds as many indexes as it can.
    NoSpace,
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProvisionError::Defined => "the EK certificate index is already defined",
            ProvisionError::Size => "the EK certificate is empty or larger than an NV index",
            ProvisionError::NoSpace => "the TPM has no free NV index for the EK certificate",
        })
    }
}

impl std::error::Error for ProvisionError {}
