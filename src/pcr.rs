// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform Configuration Registers.
//!
//! 24 PCRs in one SHA-256 bank, with the PC Client attributes the TCG reference implementation
//! uses (`TPMCmd/Platform/src/PlatformPcr.c`): which localities may extend or reset each PCR,
//! which reset to all ones, and which are left out of the update counter.

use crate::Locality;
use crate::alg::{Digest, HASHES, Hash};
use crate::handle::handle_type;
use crate::rc::Fmt1;
use crate::wire::{Reader, Writer};

pub const PCR_COUNT: usize = 24;

/// `sizeofSelect` must be exactly this: 24 PCRs is 3 bytes, and the platform has 24.
pub const PCR_SELECT_SIZE: u8 = 3;

/// The digests one `TPM2_PCR_Read` returns at most (`TPML_DIGEST`).
const MAX_READ: usize = 8;

/// A PCR that exists. Only [`PcrIndex::from_handle`] and the selection bitmap make one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PcrIndex(u8);

impl PcrIndex {
    pub fn from_handle(h: u32) -> Option<PcrIndex> {
        if handle_type(h) == 0 && (h as usize) < PCR_COUNT { Some(PcrIndex(h as u8)) } else { None }
    }

    pub fn get(self) -> u8 {
        self.0
    }

    fn all() -> impl Iterator<Item = PcrIndex> {
        (0..PCR_COUNT as u8).map(PcrIndex)
    }

    fn attributes(self) -> Attributes {
        ATTRIBUTES[self.0 as usize]
    }
}

#[derive(Clone, Copy)]
struct Attributes {
    /// Restored by `TPM2_Startup(STATE)` after `TPM2_Shutdown(STATE)`.
    state_saved: bool,
    /// Left out of the PCR update counter (the TCB group).
    no_increment: bool,
    /// Localities that may reset it; a PCR resettable from locality 4 starts as all ones.
    reset: u8,
    /// Localities that may extend it.
    extend: u8,
}

const fn a(state_saved: bool, no_increment: bool, reset: u8, extend: u8) -> Attributes {
    Attributes { state_saved, no_increment, reset, extend }
}

const STATIC: Attributes = a(true, false, 0x00, 0x1F);
const ATTRIBUTES: [Attributes; PCR_COUNT] = [
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC, //
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,
    STATIC,                      //
    a(false, false, 0x0F, 0x1F), // 16: debug
    a(false, false, 0x10, 0x1C), // 17: locality 4
    a(false, false, 0x10, 0x1C), // 18: locality 3
    a(false, false, 0x10, 0x0C), // 19: locality 2
    a(false, true, 0x14, 0x0E),  // 20: locality 1
    a(false, true, 0x14, 0x04),  // 21: dynamic OS
    a(false, true, 0x14, 0x04),  // 22: dynamic OS
    a(false, false, 0x0F, 0x1F), // 23: application
];

/// A `TPMS_PCR_SELECTION` for an implemented bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub hash: Hash,
    bits: [u8; PCR_SELECT_SIZE as usize],
}

impl Selection {
    /// Every PCR in `hash`'s bank, as `TPM_CAP_PCRS` reports an allocated bank.
    pub const fn all(hash: Hash) -> Selection {
        Selection { hash, bits: [0xFF; PCR_SELECT_SIZE as usize] }
    }

    fn contains(&self, p: PcrIndex) -> bool {
        self.bits[(p.0 / 8) as usize] & (1 << (p.0 % 8)) != 0
    }

    fn clear(&mut self, p: PcrIndex) {
        self.bits[(p.0 / 8) as usize] &= !(1 << (p.0 % 8));
    }

    pub fn write(&self, w: &mut Writer) {
        self.hash.write(w);
        w.u8(PCR_SELECT_SIZE);
        w.bytes(&self.bits);
    }

    /// Reads a `TPMS_PCR_SELECTION`: an implemented hash (else `TPM_RC_HASH`) and a bitmap of
    /// exactly `PCR_SELECT_SIZE` bytes (else `TPM_RC_VALUE`).
    pub fn read(r: &mut Reader<'_>) -> Result<Selection, Fmt1> {
        let hash = Hash::read(r)?;
        if r.u8()? != PCR_SELECT_SIZE {
            return Err(Fmt1::Value);
        }
        let mut bits = [0u8; PCR_SELECT_SIZE as usize];
        bits.copy_from_slice(r.bytes(PCR_SELECT_SIZE as usize)?);
        Ok(Selection { hash, bits })
    }
}

impl crate::marshal::Marshal for Selection {
    fn write(&self, w: &mut Writer) {
        Selection::write(self, w);
    }
}

impl crate::marshal::Unmarshal for Selection {
    fn read(r: &mut Reader<'_>) -> Result<Selection, Fmt1> {
        Selection::read(r)
    }
}

/// A `TPML_PCR_SELECTION`: at most one selection per implemented hash.
pub fn read_selection_list(r: &mut Reader<'_>) -> Result<Vec<Selection>, Fmt1> {
    let count = r.u32()?;
    if count as usize > HASHES.len() {
        return Err(Fmt1::Size);
    }
    (0..count).map(|_| Selection::read(r)).collect()
}

pub fn write_selection_list(w: &mut Writer, list: &[Selection]) {
    w.u32(list.len() as u32);
    for s in list {
        s.write(w);
    }
}

/// The PCR bank and the update counter. Lives only while the TPM is running: `_TPM_Init`
/// drops it and `TPM2_Startup` builds a new one.
#[derive(Clone)]
pub struct Pcrs {
    sha256: [Digest; PCR_COUNT],
    counter: u32,
}

impl Pcrs {
    /// The bank as `TPM2_Startup(CLEAR)` leaves it. Every PCR counts as changed, so the counter
    /// ends at the number of PCRs outside the TCB group.
    pub fn reset(startup_locality: Locality) -> Pcrs {
        let mut pcrs = Pcrs { sha256: [Digest::zero(Hash::Sha256); PCR_COUNT], counter: 0 };
        for p in PcrIndex::all() {
            let attrs = p.attributes();
            let mut d = if attrs.reset & 0x10 != 0 {
                Digest::ones(Hash::Sha256)
            } else {
                Digest::zero(Hash::Sha256)
            };
            // PCR 0 records the locality TPM2_Startup came from (the H-CRTM convention).
            if p.0 == 0 {
                let Digest::Sha256(bytes) = &mut d;
                bytes[31] = startup_locality.get();
            }
            pcrs.sha256[p.0 as usize] = d;
            pcrs.changed(p);
        }
        pcrs
    }

    /// The bank as `TPM2_Startup(STATE)` leaves it after `TPM2_Shutdown(STATE)`: the state-saved
    /// PCRs (0 to 15) and the counter as they were saved, every other PCR reset and counted as
    /// changed.
    pub fn resume(saved: &Pcrs, startup_locality: Locality) -> Pcrs {
        let reset = Pcrs::reset(startup_locality);
        let mut pcrs = Pcrs { sha256: reset.sha256, counter: saved.counter };
        for p in PcrIndex::all() {
            if p.attributes().state_saved {
                pcrs.sha256[p.0 as usize] = saved.sha256[p.0 as usize];
            } else {
                pcrs.changed(p);
            }
        }
        pcrs
    }

    /// The bank as `TPM2_Startup(CLEAR)` after `TPM2_Shutdown(STATE)` leaves it (a TPM
    /// Restart): every PCR reset, but the counter carries on from the saved one.
    pub fn restart(saved: &Pcrs, startup_locality: Locality) -> Pcrs {
        let mut pcrs = Pcrs::reset(startup_locality);
        pcrs.counter = saved.counter.wrapping_add(pcrs.counter);
        pcrs
    }

    /// Whether `TPM2_Shutdown(STATE)` saves this PCR. Changing one after the Shutdown makes the
    /// save stale.
    pub fn is_state_saved(p: PcrIndex) -> bool {
        p.attributes().state_saved
    }

    /// The digest of the selected PCRs' values in index order (`PCRComputeCurrentDigest`),
    /// with the selection as the TPM applied it.
    pub fn digest(&self, hash: Hash, selection: Vec<Selection>) -> (Vec<Selection>, Digest) {
        let mut values = Vec::new();
        for s in &selection {
            for p in PcrIndex::all() {
                if s.contains(p) {
                    values.push(self.sha256[p.0 as usize]);
                }
            }
        }
        let parts: Vec<&[u8]> = values.iter().map(Digest::as_slice).collect();
        (selection, hash.digest(&parts))
    }

    fn changed(&mut self, p: PcrIndex) {
        if !p.attributes().no_increment {
            self.counter = self.counter.wrapping_add(1);
        }
    }

    /// The update counter (`pcrUpdateCounter`), which a policy session that ran `TPM2_PolicyPCR`
    /// remembers.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn may_extend(p: PcrIndex, locality: Locality) -> bool {
        p.attributes().extend & locality.bit() != 0
    }

    /// Extends one PCR with one digest. A digest for a bank that is not allocated would be
    /// ignored; with one implemented hash and one allocated bank there is no such digest.
    pub fn extend(&mut self, p: PcrIndex, d: &Digest) {
        let slot = &mut self.sha256[p.0 as usize];
        let h = d.hash();
        *slot = h.digest(&[slot.as_slice(), d.as_slice()]);
        self.changed(p);
    }

    /// `TPM2_PCR_Read`: the PCRs selected, in bank and index order, at most eight. The returned
    /// selection is the request with every PCR that was not returned cleared.
    pub fn read(&self, mut selection: Vec<Selection>) -> (u32, Vec<Selection>, Vec<Digest>) {
        let mut out = Vec::new();
        for s in selection.iter_mut() {
            for p in PcrIndex::all() {
                if !s.contains(p) {
                    continue;
                }
                if out.len() == MAX_READ {
                    s.clear(p);
                    continue;
                }
                out.push(self.sha256[p.0 as usize]);
            }
        }
        (self.counter, selection, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_values_follow_the_pc_client_table() {
        let pcrs = Pcrs::reset(Locality::ZERO);
        assert_eq!(pcrs.sha256[0], Digest::zero(Hash::Sha256));
        assert_eq!(pcrs.sha256[16], Digest::zero(Hash::Sha256));
        for p in 17..=22 {
            assert_eq!(pcrs.sha256[p], Digest::ones(Hash::Sha256), "PCR {p}");
        }
        assert_eq!(pcrs.sha256[23], Digest::zero(Hash::Sha256));
        // 24 PCRs changed, 20-22 are the TCB group.
        assert_eq!(pcrs.counter, 21);
    }

    #[test]
    fn a_read_returns_at_most_eight_and_trims_the_selection_to_match() {
        let pcrs = Pcrs::reset(Locality::ZERO);
        let (_, sel, digests) = pcrs.read(vec![Selection::all(Hash::Sha256)]);
        assert_eq!(digests.len(), 8);
        assert_eq!(sel[0].bits, [0xFF, 0, 0]);
    }
}
