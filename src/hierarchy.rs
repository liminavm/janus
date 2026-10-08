// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four hierarchies, their primary seeds and their proof values.
//!
//! A hierarchy's seed is what its primary keys are derived from, and its proof is the secret
//! that makes its tickets and saved contexts unforgeable. The platform, storage and endorsement
//! values are generated at manufacture and live for the life of the TPM; the null hierarchy's
//! are generated again at every TPM Reset, which is what makes everything created under it
//! ephemeral.

use crate::Platform;
use crate::handle::rh;
use crate::marshal::{Marshal, Unmarshal};
use crate::rc::Fmt1;
use crate::wire::{Reader, Writer};
use zeroize::Zeroizing;

/// A primary seed or a proof value: as long as a SHA-256 digest (`PRIMARY_SEED_SIZE`,
/// `PROOF_SIZE`).
pub const SECRET_SIZE: usize = 32;

/// A hierarchy (`TPMI_RH_HIERARCHY+`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hierarchy {
    Platform,
    Owner,
    Endorsement,
    Null,
}

impl Hierarchy {
    /// `TPMI_RH_HIERARCHY`, with `TPM_RH_NULL` accepted only when `allow_null`. Anything else is
    /// `TPM_RC_VALUE`.
    pub const fn from_handle(h: u32, allow_null: bool) -> Option<Hierarchy> {
        match h {
            rh::PLATFORM => Some(Hierarchy::Platform),
            rh::OWNER => Some(Hierarchy::Owner),
            rh::ENDORSEMENT => Some(Hierarchy::Endorsement),
            rh::NULL if allow_null => Some(Hierarchy::Null),
            _ => None,
        }
    }

    pub const fn handle(self) -> u32 {
        match self {
            Hierarchy::Platform => rh::PLATFORM,
            Hierarchy::Owner => rh::OWNER,
            Hierarchy::Endorsement => rh::ENDORSEMENT,
            Hierarchy::Null => rh::NULL,
        }
    }
}

impl crate::marshal::Marshal for Hierarchy {
    fn write(&self, w: &mut crate::wire::Writer) {
        w.u32(self.handle());
    }
}

impl crate::marshal::Unmarshal for Hierarchy {
    fn read(r: &mut crate::wire::Reader<'_>) -> Result<Hierarchy, crate::rc::Fmt1> {
        Hierarchy::from_handle(r.u32()?, true).ok_or(crate::rc::Fmt1::Value)
    }
}

/// A seed or proof. Zeroized on drop; never printed or cloned.
pub struct HierarchySecret(Zeroizing<[u8; SECRET_SIZE]>);

impl HierarchySecret {
    pub fn generate(platform: &mut impl Platform) -> HierarchySecret {
        let mut s = Zeroizing::new([0u8; SECRET_SIZE]);
        platform.fill_random(&mut s[..]);
        HierarchySecret(s)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// The values made at manufacture: one seed and one proof per persistent hierarchy.
pub struct PersistentSecrets {
    pub platform_seed: HierarchySecret,
    pub storage_seed: HierarchySecret,
    pub endorsement_seed: HierarchySecret,
    pub platform_proof: HierarchySecret,
    pub storage_proof: HierarchySecret,
    pub endorsement_proof: HierarchySecret,
}

impl PersistentSecrets {
    pub fn generate(platform: &mut impl Platform) -> PersistentSecrets {
        PersistentSecrets {
            platform_seed: HierarchySecret::generate(platform),
            storage_seed: HierarchySecret::generate(platform),
            endorsement_seed: HierarchySecret::generate(platform),
            platform_proof: HierarchySecret::generate(platform),
            storage_proof: HierarchySecret::generate(platform),
            endorsement_proof: HierarchySecret::generate(platform),
        }
    }
}

/// The null hierarchy's values, made again at every TPM Reset.
pub struct NullSecrets {
    pub seed: HierarchySecret,
    pub proof: HierarchySecret,
}

impl NullSecrets {
    pub fn generate(platform: &mut impl Platform) -> NullSecrets {
        NullSecrets {
            seed: HierarchySecret::generate(platform),
            proof: HierarchySecret::generate(platform),
        }
    }
}

/// Both sets, for looking up a hierarchy's seed or proof.
pub struct Secrets<'a> {
    pub persistent: &'a PersistentSecrets,
    pub null: &'a NullSecrets,
}

impl<'a> Secrets<'a> {
    pub fn seed(&self, h: Hierarchy) -> &'a [u8] {
        match h {
            Hierarchy::Platform => self.persistent.platform_seed.as_bytes(),
            Hierarchy::Owner => self.persistent.storage_seed.as_bytes(),
            Hierarchy::Endorsement => self.persistent.endorsement_seed.as_bytes(),
            Hierarchy::Null => self.null.seed.as_bytes(),
        }
    }

    pub fn proof(&self, h: Hierarchy) -> &'a [u8] {
        match h {
            Hierarchy::Platform => self.persistent.platform_proof.as_bytes(),
            Hierarchy::Owner => self.persistent.storage_proof.as_bytes(),
            Hierarchy::Endorsement => self.persistent.endorsement_proof.as_bytes(),
            Hierarchy::Null => self.null.proof.as_bytes(),
        }
    }
}

// In the state file: each secret as its bytes, in field order.

impl Marshal for HierarchySecret {
    fn write(&self, w: &mut Writer) {
        w.bytes(&self.0[..]);
    }
}

impl Unmarshal for HierarchySecret {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let mut s = Zeroizing::new([0u8; SECRET_SIZE]);
        s.copy_from_slice(r.bytes(SECRET_SIZE)?);
        Ok(HierarchySecret(s))
    }
}

impl Marshal for PersistentSecrets {
    fn write(&self, w: &mut Writer) {
        self.platform_seed.write(w);
        self.storage_seed.write(w);
        self.endorsement_seed.write(w);
        self.platform_proof.write(w);
        self.storage_proof.write(w);
        self.endorsement_proof.write(w);
    }
}

impl Unmarshal for PersistentSecrets {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(PersistentSecrets {
            platform_seed: HierarchySecret::read(r)?,
            storage_seed: HierarchySecret::read(r)?,
            endorsement_seed: HierarchySecret::read(r)?,
            platform_proof: HierarchySecret::read(r)?,
            storage_proof: HierarchySecret::read(r)?,
            endorsement_proof: HierarchySecret::read(r)?,
        })
    }
}

impl Marshal for NullSecrets {
    fn write(&self, w: &mut Writer) {
        self.seed.write(w);
        self.proof.write(w);
    }
}

impl Unmarshal for NullSecrets {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(NullSecrets { seed: HierarchySecret::read(r)?, proof: HierarchySecret::read(r)? })
    }
}
