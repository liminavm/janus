// SPDX-License-Identifier: MIT OR Apache-2.0

//! Algorithm identifiers (`TPM_ALG_ID`, Part 2 §6.3) and the hashes this TPM implements.

use crate::rc::Fmt1;
use crate::wire::{Reader, Writer};
use sha2::Digest as _;

/// `TPM_ALG_ID` values the engine names.
pub mod id {
    pub const AES: u16 = 0x0006;
    pub const SHA256: u16 = 0x000B;
}

/// A hash this TPM implements. It has one PCR bank, SHA-256, and SHA-256 is the only hash it
/// computes; an algorithm outside this enum is not implemented, and a `TPMI_ALG_HASH` naming
/// one is `TPM_RC_HASH`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
}

/// The implemented hashes, in `TPM_ALG_ID` order.
pub const HASHES: [Hash; 1] = [Hash::Sha256];

/// The largest digest any implemented hash produces.
pub const MAX_DIGEST: usize = 32;

impl Hash {
    pub const fn id(self) -> u16 {
        match self {
            Hash::Sha256 => id::SHA256,
        }
    }

    pub const fn from_id(id: u16) -> Option<Hash> {
        match id {
            id::SHA256 => Some(Hash::Sha256),
            _ => None,
        }
    }

    /// Reads a `TPMI_ALG_HASH` that may not be `TPM_ALG_NULL`.
    pub fn read(r: &mut Reader<'_>) -> Result<Hash, Fmt1> {
        Hash::from_id(r.u16()?).ok_or(Fmt1::Hash)
    }

    pub fn write(self, w: &mut Writer) {
        w.u16(self.id());
    }

    /// The digest of the concatenation of `parts`.
    pub fn digest(self, parts: &[&[u8]]) -> Digest {
        match self {
            Hash::Sha256 => {
                let mut h = sha2::Sha256::new();
                for p in parts {
                    h.update(p);
                }
                let out: [u8; 32] = h.finalize().into();
                Digest::Sha256(out)
            }
        }
    }
}

/// A digest, tagged with the hash that made it, so its length can never disagree with its
/// algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    Sha256([u8; 32]),
}

impl Digest {
    pub const fn zero(h: Hash) -> Digest {
        match h {
            Hash::Sha256 => Digest::Sha256([0; 32]),
        }
    }

    pub const fn ones(h: Hash) -> Digest {
        match h {
            Hash::Sha256 => Digest::Sha256([0xFF; 32]),
        }
    }

    pub const fn hash(&self) -> Hash {
        match self {
            Digest::Sha256(_) => Hash::Sha256,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Digest::Sha256(d) => d,
        }
    }

    /// Reads a `TPMT_HA`: a hash algorithm, then exactly that algorithm's digest size of bytes.
    pub fn read_tagged(r: &mut Reader<'_>) -> Result<Digest, Fmt1> {
        match Hash::read(r)? {
            Hash::Sha256 => {
                let mut d = [0u8; 32];
                d.copy_from_slice(r.bytes(32)?);
                Ok(Digest::Sha256(d))
            }
        }
    }
}
