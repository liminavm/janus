// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hash sequence objects: `TPM2_HashSequenceStart`, `TPM2_SequenceUpdate`,
//! `TPM2_SequenceComplete`.
//!
//! A sequence lives in an object slot and, like any transient object, is saved and loaded as a
//! context while it runs: the kernel's resource manager saves every transient object after each
//! command. So its hash state must marshal, and the format is janus's own (the SHA-256 chaining
//! value, the bytes of an unfinished block, the length) rather than a library's, for the same
//! reason a key's derivation is janus's own: it outlives the library version that wrote it.

use crate::alg::MAX_DIGEST;
use crate::marshal::{Marshal, Unmarshal};
use crate::rc::Fmt1;
use crate::types::Secret;
use crate::wire::{Reader, Writer};
use zeroize::{Zeroize, Zeroizing};

/// SHA-256 in progress, built on the block function so its state is ours to marshal.
#[derive(Clone)]
pub struct Sha256State {
    h: [u32; 8],
    /// The bytes of an unfinished block: `len % 64` of them.
    pending: Zeroizing<Vec<u8>>,
    /// Bytes hashed so far.
    len: u64,
}

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

impl Default for Sha256State {
    fn default() -> Self {
        Sha256State { h: H0, pending: Zeroizing::new(Vec::new()), len: 0 }
    }
}

impl Sha256State {
    pub fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        self.pending.extend_from_slice(data);
        let (blocks, rest) = self.pending.as_chunks::<64>();
        sha2::block_api::compress256(&mut self.h, blocks);
        let whole = self.pending.len() - rest.len();
        self.pending.drain(..whole);
    }

    /// FIPS 180-4 §5.1.1 padding: `0x80`, zeros, and the length in bits.
    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        let mut tail = vec![0x80u8];
        let used = (self.pending.len() + 1) % 64;
        tail.resize(1 + (64 + 56 - used) % 64, 0);
        tail.extend_from_slice(&bits.to_be_bytes());
        self.update(&tail);
        debug_assert!(self.pending.is_empty());
        let mut out = [0u8; 32];
        for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            *o = w.to_be_bytes();
        }
        self.h.zeroize();
        out
    }
}

impl Marshal for Sha256State {
    fn write(&self, w: &mut Writer) {
        for x in self.h {
            w.u32(x);
        }
        w.u64(self.len);
        w.tpm2b(&self.pending);
    }
}

impl Unmarshal for Sha256State {
    /// The pending bytes must be exactly the length's remainder in a block, or the state is
    /// not one a hash could have reached (`TPM_RC_VALUE`).
    fn read(r: &mut Reader<'_>) -> Result<Sha256State, Fmt1> {
        let mut h = [0u32; 8];
        for x in &mut h {
            *x = r.u32()?;
        }
        let len = r.u64()?;
        let pending = r.tpm2b::<63>()?;
        if pending.get().len() as u64 != len % 64 {
            return Err(Fmt1::Value);
        }
        Ok(Sha256State { h, pending: Zeroizing::new(pending.get().to_vec()), len })
    }
}

/// What a sequence computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `TPM2_HashSequenceStart` with a hash: `TPM2_SequenceComplete` ends it.
    Hash {
        /// The first `TPM2_SequenceUpdate` has run; whether the data starts like something the
        /// TPM signs was decided then.
        first_block: bool,
        /// The data does not start with `TPM_GENERATED_VALUE`, so its digest may be ticketed.
        ticket_safe: bool,
    },
    /// `TPM2_HashSequenceStart` with `TPM_ALG_NULL`: an event sequence, which only
    /// `TPM2_EventSequenceComplete` (not implemented) ends.
    Event,
}

/// A hash or event sequence object.
pub struct HashSequence {
    pub auth: Secret<MAX_DIGEST>,
    pub kind: Kind,
    pub state: Sha256State,
}

impl HashSequence {
    pub fn new(auth: Secret<MAX_DIGEST>, event: bool) -> HashSequence {
        let kind =
            if event { Kind::Event } else { Kind::Hash { first_block: false, ticket_safe: false } };
        HashSequence { auth, kind, state: Sha256State::default() }
    }

    /// `TPM2_SequenceUpdate`. The first block of a hash sequence decides whether its digest may
    /// be ticketed.
    pub fn update(&mut self, data: &[u8]) {
        if let Kind::Hash { first_block: first @ false, ticket_safe } = &mut self.kind {
            *first = true;
            *ticket_safe = ticket_safe_data(data);
        }
        self.state.update(data);
    }
}

/// `TicketIsSafe`: data that starts with `TPM_GENERATED_VALUE` could be passed off as an
/// attestation, so its digest gets no ticket; nor does data too short to tell. (`TPM2_Hash`
/// tickets short data anyway: it only asks this of data at least that long.)
pub fn ticket_safe_data(data: &[u8]) -> bool {
    let generated = TPM_GENERATED_VALUE.to_be_bytes();
    data.len() >= generated.len() && !data.starts_with(&generated)
}

/// `TPM_GENERATED_VALUE`, which starts every structure the TPM signs.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

impl Marshal for HashSequence {
    fn write(&self, w: &mut Writer) {
        self.auth.write(w);
        match self.kind {
            Kind::Hash { first_block, ticket_safe } => {
                w.u8(0);
                w.u8(u8::from(first_block));
                w.u8(u8::from(ticket_safe));
            }
            Kind::Event => w.u8(1),
        }
        self.state.write(w);
    }
}

impl Unmarshal for HashSequence {
    fn read(r: &mut Reader<'_>) -> Result<HashSequence, Fmt1> {
        let auth = Secret::read(r)?;
        let kind = match r.u8()? {
            0 => Kind::Hash { first_block: bool::read(r)?, ticket_safe: bool::read(r)? },
            1 => Kind::Event,
            _ => return Err(Fmt1::Value),
        };
        Ok(HashSequence { auth, kind, state: Sha256State::read(r)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    #[test]
    fn the_state_hashes_as_sha256_across_any_split() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        let expected = sha2::Sha256::digest(&data);
        for split in [0, 1, 55, 56, 63, 64, 65, 119, 128, 299, 300] {
            let mut s = Sha256State::default();
            s.update(&data[..split]);
            // Through a marshal round trip, as a saved context takes it.
            let mut w = Writer::new();
            s.write(&mut w);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            let mut s = Sha256State::read(&mut r).unwrap();
            r.finish().unwrap();
            s.update(&data[split..]);
            assert_eq!(s.finish()[..], expected[..], "split at {split}");
        }
        for n in [0usize, 55, 56, 64] {
            let d = vec![0xA5u8; n];
            let mut s = Sha256State::default();
            s.update(&d);
            assert_eq!(s.finish()[..], sha2::Sha256::digest(&d)[..], "{n} bytes");
        }
    }

    #[test]
    fn a_state_whose_pending_bytes_disagree_with_its_length_does_not_read() {
        let mut s = Sha256State::default();
        s.update(b"abc");
        let mut w = Writer::new();
        s.write(&mut w);
        let mut bytes = w.into_vec();
        // len is at offset 32; claim one more byte than is pending.
        bytes[39] += 1;
        assert_eq!(Sha256State::read(&mut Reader::new(&bytes)).err(), Some(Fmt1::Value));
    }

    #[test]
    fn data_is_safe_to_ticket_unless_it_starts_like_an_attestation_or_is_too_short() {
        assert!(!ticket_safe_data(b""));
        assert!(!ticket_safe_data(b"\xffTC"));
        assert!(ticket_safe_data(b"abcd"));
        assert!(!ticket_safe_data(b"\xffTCG"));
        assert!(!ticket_safe_data(b"\xffTCG and more"));
        assert!(ticket_safe_data(b"x\xffTCG"));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every input of up to 48 bytes, a hash state reads only when its pending bytes are
    /// exactly its length's remainder in a block, and then consumes exactly its fields.
    #[kani::proof]
    #[kani::unwind(50)]
    fn a_hash_state_reads_only_a_state_a_hash_could_reach() {
        let data: [u8; 48] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 48);
        let mut r = Reader::new(&data[..len]);
        if let Ok(s) = Sha256State::read(&mut r) {
            let n = u16::from_be_bytes([data[40], data[41]]) as usize;
            assert!(s.pending.len() == n);
            assert!(s.len % 64 == n as u64);
            assert!(r.remaining() == len - 42 - n);
        }
    }
}
