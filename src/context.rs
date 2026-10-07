// SPDX-License-Identifier: MIT OR Apache-2.0

//! Saved contexts (`TPMS_CONTEXT`).
//!
//! A context blob is janus's own format, with the protection Part 1 §30 requires: the payload
//! (an object or a session, in its generated marshalled form) is encrypted with AES-128-CFB
//! under `KDFa(SHA-256, hierarchyProof, "CONTEXT", sequence, handle)`, and an HMAC keyed by the
//! same proof covers the TPM's reset count, the clear count for an `stClear` object, the
//! sequence, the handle and the ciphertext. A context therefore loads only into the TPM that
//! saved it, only until that TPM's next Reset (or Restart, for `stClear`), and only with the
//! sequence and handle it was saved with.
//!
//! ```text
//! contextBlob = TPM2B integrity (32 bytes) || AES-CFB(sequence (8) || payload)
//! ```

use crate::alg::Hash;
use crate::crypto;
use crate::handle::{handle_type, ht};
use crate::hierarchy::Hierarchy;
use crate::marshal::{Marshal, Unmarshal};
use crate::rc::Fmt1;
use crate::session::MAX_ACTIVE_SESSIONS;
use crate::wire::{Buf, Reader, Writer};
use zeroize::Zeroizing;

/// The context HMAC's size, SHA-256.
const INTEGRITY_SIZE: usize = 32;
const FINGERPRINT_SIZE: usize = 8;

/// The largest object payload: an RSA-2048 public area (316 bytes), its sensitive area (200),
/// the hierarchy (4) and the qualified name (36).
pub const MAX_OBJECT_PAYLOAD: usize = 316 + 200 + 4 + 36;
/// The largest session payload: the selector (1), the common part (78) and the policy part
/// (45).
pub const MAX_SESSION_PAYLOAD: usize = 1 + 78 + 45;
/// The largest `TPM2B_CONTEXT_DATA` janus makes or accepts.
pub const MAX_CONTEXT_SIZE: usize = 2 + INTEGRITY_SIZE + FINGERPRINT_SIZE + MAX_OBJECT_PAYLOAD;

/// `TPM_PT_MAX_OBJECT_CONTEXT` and `TPM_PT_MAX_SESSION_CONTEXT`: the largest whole
/// `TPMS_CONTEXT` for each, which is what a resource manager sizes its buffers from.
pub const MAX_OBJECT_CONTEXT: usize = 8 + 4 + 4 + 2 + INTEGRITY_SIZE + 2 + 8 + MAX_OBJECT_PAYLOAD;
pub const MAX_SESSION_CONTEXT: usize = 8 + 4 + 4 + 2 + INTEGRITY_SIZE + 2 + 8 + MAX_SESSION_PAYLOAD;

/// What a saved context holds (`TPMI_DH_SAVED`): an object, by kind, or a session, by the
/// handle it goes back to. Any other value is `TPM_RC_VALUE` when the context is read, so a
/// context in hand always names something a context can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedHandle {
    Object,
    /// A hash or event sequence object. None can be saved yet.
    Sequence,
    /// An object with `stClear`, whose context also dies at TPM Restart.
    StClear,
    Session(u32),
}

const SAVED_OBJECT: u32 = 0x8000_0000;
const SAVED_SEQUENCE: u32 = 0x8000_0001;
const SAVED_ST_CLEAR: u32 = 0x8000_0002;

impl SavedHandle {
    pub const fn value(self) -> u32 {
        match self {
            SavedHandle::Object => SAVED_OBJECT,
            SavedHandle::Sequence => SAVED_SEQUENCE,
            SavedHandle::StClear => SAVED_ST_CLEAR,
            SavedHandle::Session(h) => h,
        }
    }

    pub fn from_value(h: u32) -> Option<SavedHandle> {
        match h {
            SAVED_OBJECT => Some(SavedHandle::Object),
            SAVED_SEQUENCE => Some(SavedHandle::Sequence),
            SAVED_ST_CLEAR => Some(SavedHandle::StClear),
            _ => {
                let t = handle_type(h);
                let in_range = (h & 0x00FF_FFFF) < MAX_ACTIVE_SESSIONS as u32;
                ((t == ht::HMAC_SESSION || t == ht::POLICY_SESSION) && in_range)
                    .then_some(SavedHandle::Session(h))
            }
        }
    }
}

impl Marshal for SavedHandle {
    fn write(&self, w: &mut Writer) {
        w.u32(self.value());
    }
}

impl Unmarshal for SavedHandle {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        SavedHandle::from_value(r.u32()?).ok_or(Fmt1::Value)
    }
}

wire_struct! {
    /// `TPMS_CONTEXT`.
    pub struct Context {
        pub sequence: u64,
        pub saved_handle: SavedHandle,
        pub hierarchy: Hierarchy,
        pub blob: Buf<MAX_CONTEXT_SIZE>,
    }
}

/// What the integrity HMAC binds a context to besides its own fields.
pub struct Epoch {
    /// Increments at every TPM Reset and never goes back (`totalResetCount`).
    pub reset_count: u64,
    /// Increments at every TPM Restart and resets at TPM Reset (`clearCount`).
    pub clear_count: u32,
}

fn keys(proof: &[u8], sequence: u64, handle: SavedHandle) -> (Zeroizing<[u8; 16]>, [u8; 16]) {
    let bits = crypto::kdfa(
        Hash::Sha256,
        proof,
        b"CONTEXT",
        &sequence.to_be_bytes(),
        &handle.value().to_be_bytes(),
        256,
    );
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&bits[..16]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&bits[16..]);
    (key, iv)
}

fn integrity(
    proof: &[u8],
    epoch: &Epoch,
    sequence: u64,
    handle: SavedHandle,
    encrypted: &[u8],
) -> Zeroizing<Vec<u8>> {
    let reset = epoch.reset_count.to_be_bytes();
    let clear = epoch.clear_count.to_be_bytes();
    let seq = sequence.to_be_bytes();
    let h = handle.value().to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&reset];
    if handle == SavedHandle::StClear {
        parts.push(&clear);
    }
    parts.extend([&seq[..], &h[..], encrypted]);
    crypto::hmac(Hash::Sha256, proof, &parts)
}

/// Seals `payload` into a context blob.
pub fn seal(
    proof: &[u8],
    epoch: &Epoch,
    sequence: u64,
    handle: SavedHandle,
    payload: &impl Marshal,
) -> Buf<MAX_CONTEXT_SIZE> {
    let mut plain = Writer::new();
    plain.u64(sequence);
    payload.write(&mut plain);
    let mut data = Zeroizing::new(plain.into_vec());
    let (key, iv) = keys(proof, sequence, handle);
    crypto::aes128_cfb_encrypt(&key, &iv, &mut data);
    let tag = integrity(proof, epoch, sequence, handle, &data);
    let mut blob = Writer::new();
    blob.tpm2b(&tag);
    blob.bytes(&data);
    Buf::from_slice(&blob.into_vec()).expect("a context payload is within MAX_CONTEXT_SIZE")
}

/// Why a context blob does not open, positioned by the caller on the context parameter.
pub type Refused = Fmt1;

/// Opens a context blob: `TPM_RC_SIZE` for a malformed one, `TPM_RC_INTEGRITY` for one this
/// TPM did not seal under these values. The payload is decoded as `T`; a payload that passes
/// the HMAC but does not decode can only be an engine bug, and is refused as integrity too.
pub fn open<T: Unmarshal>(proof: &[u8], epoch: &Epoch, context: &Context) -> Result<T, Refused> {
    let mut r = Reader::new(context.blob.as_slice());
    let tag = r.tpm2b::<INTEGRITY_SIZE>().map_err(|_| Fmt1::Size)?;
    if tag.get().len() != INTEGRITY_SIZE || r.remaining() < FINGERPRINT_SIZE {
        return Err(Fmt1::Size);
    }
    let encrypted = r.bytes(r.remaining()).expect("remaining bytes are there");
    let expected = integrity(proof, epoch, context.sequence, context.saved_handle, encrypted);
    if !crypto::constant_time_eq(&expected, tag.get()) {
        return Err(Fmt1::Integrity);
    }
    let mut data = Zeroizing::new(encrypted.to_vec());
    let (key, iv) = keys(proof, context.sequence, context.saved_handle);
    crypto::aes128_cfb_decrypt(&key, &iv, &mut data);
    let mut p = Reader::new(&data);
    let fingerprint = p.u64().map_err(|_| Fmt1::Integrity)?;
    if fingerprint != context.sequence {
        return Err(Fmt1::Integrity);
    }
    let t = T::read(&mut p).map_err(|_| Fmt1::Integrity)?;
    p.finish().map_err(|_| Fmt1::Integrity)?;
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    use SavedHandle::{Object as SAVED_OBJECT, StClear as SAVED_ST_CLEAR};

    fn ctx(blob: Buf<MAX_CONTEXT_SIZE>, sequence: u64, handle: SavedHandle) -> Context {
        Context { sequence, saved_handle: handle, hierarchy: Hierarchy::Null, blob }
    }

    /// The largest object and session the types can hold marshal to exactly the payload
    /// bounds, so `seal`'s buffer always fits and `TPM_PT_MAX_*_CONTEXT` tell the truth.
    #[test]
    fn the_largest_payloads_are_the_bounds() {
        use crate::object::Object;
        use crate::session::Session;
        let mut o = Vec::new();
        // TPMT_PUBLIC: RSA, SHA-256, a signing key, a full policy, AES-128-CFB, RSASSA-SHA256,
        // 2048 bits, an explicit exponent, a full modulus.
        o.extend_from_slice(&[0x00, 0x01, 0x00, 0x0B, 0x00, 0x04, 0x00, 0x72, 0x00, 0x20]);
        o.extend_from_slice(&[0xAA; 32]);
        o.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x14, 0x00, 0x0B]);
        o.extend_from_slice(&[0x08, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00]);
        o.extend_from_slice(&[0xBB; 256]);
        // TPMT_SENSITIVE: RSA, a full authValue and seed, a full prime.
        o.extend_from_slice(&[0x00, 0x01, 0x00, 0x20]);
        o.extend_from_slice(&[0xCC; 32]);
        o.extend_from_slice(&[0x00, 0x20]);
        o.extend_from_slice(&[0xDD; 32]);
        o.extend_from_slice(&[0x00, 0x80]);
        o.extend_from_slice(&[0xEE; 128]);
        // The hierarchy and a full qualified name.
        o.extend_from_slice(&[0x40, 0x00, 0x00, 0x01, 0x00, 0x22, 0x00, 0x0B]);
        o.extend_from_slice(&[0xFF; 32]);
        let (object, n) = crate::marshal::read_prefix::<Object>(&o).unwrap();
        assert_eq!(n, o.len());
        assert_eq!(o.len(), MAX_OBJECT_PAYLOAD);
        let epoch = Epoch { reset_count: 1, clear_count: 0 };
        let blob = seal(&[1; 32], &epoch, u64::MAX, SAVED_OBJECT, &object);
        assert_eq!(blob.as_slice().len(), MAX_CONTEXT_SIZE);

        let mut s = Vec::new();
        // A policy session: AES-128-CFB, full nonce, key and digest, both options present.
        s.push(crate::handle::ht::POLICY_SESSION);
        s.extend_from_slice(&[0x00, 0x0B, 0x00, 0x20]);
        s.extend_from_slice(&[0x11; 32]);
        s.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x20]);
        s.extend_from_slice(&[0x22; 32]);
        s.extend_from_slice(&[1, 1, 0]);
        s.extend_from_slice(&[0x33; 32]);
        s.extend_from_slice(&[1, 1, 1, 0, 0, 1, 0x7F, 1, 0, 0, 0, 9]);
        let (session, n) = crate::marshal::read_prefix::<Session>(&s).unwrap();
        assert_eq!(n, s.len());
        assert_eq!(s.len(), MAX_SESSION_PAYLOAD);
        seal(&[1; 32], &epoch, u64::MAX, SavedHandle::Session(0x0300_0000), &session);
    }

    /// The blob's bytes for fixed inputs. A saved context outlives the janus that made it (a
    /// guest's resource manager holds contexts across a suspend), so its format is pinned: the
    /// integrity HMAC over the reset count, the sequence, the handle and the ciphertext, and
    /// the cipher keyed from the proof, the sequence and the handle.
    #[test]
    fn the_context_format_is_pinned() {
        let epoch = Epoch { reset_count: 3, clear_count: 1 };
        let blob = seal(&[7; 32], &epoch, 5, SAVED_OBJECT, &0xDEAD_BEEFu32);
        let bytes = blob.as_slice();
        // Part 1 §30.4: HMAC(proof, resetValue || sequence || handle || encContext).
        let tag = crypto::hmac(
            Hash::Sha256,
            &[7; 32],
            &[
                &3u64.to_be_bytes(),
                &5u64.to_be_bytes(),
                &0x8000_0000u32.to_be_bytes(),
                &bytes[34..],
            ],
        );
        assert_eq!(bytes[..2], [0, 32]);
        assert_eq!(&bytes[2..34], &tag[..]);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "0020627e94da474e64f1db65056e861a4e5e12067830572d392c0c25fa0b7a218f0b9e",
                "dfc4c4f53febbe942ef2c7"
            )
        );
    }

    #[test]
    fn a_context_opens_only_as_it_was_sealed() {
        let epoch = Epoch { reset_count: 3, clear_count: 1 };
        let blob = seal(&[7; 32], &epoch, 5, SAVED_OBJECT, &0xDEAD_BEEFu32);
        let ok: u32 = open(&[7; 32], &epoch, &ctx(blob.clone(), 5, SAVED_OBJECT)).unwrap();
        assert_eq!(ok, 0xDEAD_BEEF);
        // Another proof, sequence, handle or reset count: integrity.
        assert_eq!(
            open::<u32>(&[8; 32], &epoch, &ctx(blob.clone(), 5, SAVED_OBJECT)),
            Err(Fmt1::Integrity)
        );
        assert_eq!(
            open::<u32>(&[7; 32], &epoch, &ctx(blob.clone(), 6, SAVED_OBJECT)),
            Err(Fmt1::Integrity)
        );
        assert_eq!(
            open::<u32>(&[7; 32], &epoch, &ctx(blob.clone(), 5, SAVED_ST_CLEAR)),
            Err(Fmt1::Integrity)
        );
        let later = Epoch { reset_count: 4, clear_count: 1 };
        assert_eq!(
            open::<u32>(&[7; 32], &later, &ctx(blob.clone(), 5, SAVED_OBJECT)),
            Err(Fmt1::Integrity)
        );
        // An ordinary object survives a Restart; an stClear one does not.
        let restarted = Epoch { reset_count: 3, clear_count: 2 };
        assert!(open::<u32>(&[7; 32], &restarted, &ctx(blob, 5, SAVED_OBJECT)).is_ok());
        let st = seal(&[7; 32], &epoch, 5, SAVED_ST_CLEAR, &1u32);
        assert_eq!(
            open::<u32>(&[7; 32], &restarted, &ctx(st, 5, SAVED_ST_CLEAR)),
            Err(Fmt1::Integrity)
        );
        // A flipped ciphertext bit.
        let mut bytes = seal(&[7; 32], &epoch, 5, SAVED_OBJECT, &1u32).as_slice().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = Buf::from_slice(&bytes).unwrap();
        assert_eq!(
            open::<u32>(&[7; 32], &epoch, &ctx(tampered, 5, SAVED_OBJECT)),
            Err(Fmt1::Integrity)
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// TPMI_DH_SAVED: the three object values, and a handle of either session type whose index
    /// is inside the session table. Nothing else.
    #[kani::proof]
    fn saved_handles_are_exactly_tpmi_dh_saved() {
        let h: u32 = kani::any();
        let session = (handle_type(h) == ht::HMAC_SESSION || handle_type(h) == ht::POLICY_SESSION)
            && (h & 0x00FF_FFFF) < MAX_ACTIVE_SESSIONS as u32;
        let object = h == SAVED_OBJECT || h == SAVED_SEQUENCE || h == SAVED_ST_CLEAR;
        match SavedHandle::from_value(h) {
            Some(s) => {
                assert!(s.value() == h);
                assert!(object || session);
            }
            None => assert!(!object && !session),
        }
    }
}
