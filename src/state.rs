// SPDX-License-Identifier: MIT OR Apache-2.0

//! The state file's frame: what the TPM keeps in NV, as bytes the device stores and hands back.
//!
//! The frame is a magic, a version, the body, and a SHA-256 digest of everything before it. The
//! digest catches a truncated or damaged file; it is not a MAC, and the file is no more secret
//! or authentic than the host keeps it. The body is [`crate::Janus::state`]'s to define.

use sha2::Digest as _;
use zeroize::Zeroizing;

/// The first bytes of every state file.
const MAGIC: [u8; 8] = *b"janusTPM";
/// The body's format. A change to it is a new version, and an older one stays readable.
pub const VERSION: u16 = 1;
const HEADER: usize = MAGIC.len() + 2;
const DIGEST: usize = 32;

/// Why a state file was refused. Each means the identity it held cannot be recovered from it;
/// making a new TPM in its place would lose every secret sealed to the old one, which is the
/// caller's decision, never the engine's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// Not a janus state file.
    NotState,
    /// A format this build does not read.
    Version(u16),
    /// The digest does not match: the file was truncated or damaged.
    Damaged,
    /// The digest matches but the body does not describe a TPM this engine could have saved.
    Invalid,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StateError::NotState => write!(f, "not a janus TPM state file"),
            StateError::Version(v) => {
                write!(f, "TPM state format {v}, which this build cannot read")
            }
            StateError::Damaged => write!(f, "the TPM state file is truncated or damaged"),
            StateError::Invalid => write!(f, "the TPM state file describes no valid TPM"),
        }
    }
}

impl std::error::Error for StateError {}

/// `body` in a frame.
pub fn frame(body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER + body.len() + DIGEST));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(body);
    let digest = sha2::Sha256::digest(&out[..]);
    out.extend_from_slice(&digest);
    out
}

/// The body `bytes` frames.
pub fn unframe(bytes: &[u8]) -> Result<&[u8], StateError> {
    if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
        return Err(StateError::NotState);
    }
    if bytes.len() < HEADER + DIGEST {
        return Err(StateError::Damaged);
    }
    let (framed, digest) = bytes.split_at(bytes.len() - DIGEST);
    if sha2::Sha256::digest(framed)[..] != digest[..] {
        return Err(StateError::Damaged);
    }
    let version = u16::from_be_bytes([framed[MAGIC.len()], framed[MAGIC.len() + 1]]);
    if version != VERSION {
        return Err(StateError::Version(version));
    }
    Ok(&framed[HEADER..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_gives_back_its_body() {
        for body in [&b""[..], b"x", &[7; 300]] {
            assert_eq!(unframe(&frame(body)), Ok(body));
        }
    }

    #[test]
    fn a_damaged_or_foreign_frame_is_refused() {
        let good = frame(b"some state");
        assert_eq!(unframe(b""), Err(StateError::NotState));
        assert_eq!(unframe(b"janusTP"), Err(StateError::NotState));
        assert_eq!(
            unframe(b"notjanus and more bytes than a frame needs at all"),
            Err(StateError::NotState)
        );
        assert_eq!(unframe(&good[..good.len() - 1]), Err(StateError::Damaged));
        assert_eq!(unframe(&good[..HEADER + DIGEST - 1]), Err(StateError::Damaged));
        for i in MAGIC.len()..good.len() {
            let mut bad = good.to_vec();
            bad[i] ^= 1;
            assert_eq!(unframe(&bad), Err(StateError::Damaged), "byte {i}");
        }
        // A good digest over a version this build does not know.
        let mut other = MAGIC.to_vec();
        other.extend_from_slice(&2u16.to_be_bytes());
        other.extend_from_slice(b"body");
        let digest = sha2::Sha256::digest(&other);
        other.extend_from_slice(&digest);
        assert_eq!(unframe(&other), Err(StateError::Version(2)));
    }

    struct Zero;

    impl crate::Platform for Zero {
        fn fill_random(&mut self, buf: &mut [u8]) {
            buf.fill(0);
        }
        fn now_ms(&mut self) -> u64 {
            0
        }
    }

    /// A whole frame around a body that is not a TPM's state, or is one with more after it.
    #[test]
    fn a_frame_around_no_valid_state_is_invalid() {
        let restore = |body: &[u8]| crate::Janus::restore(Zero, &frame(body)).err();
        assert_eq!(restore(b""), Some(StateError::Invalid));
        assert_eq!(restore(&[0; 400]), Some(StateError::Invalid));
        let good = crate::Janus::manufacture(Zero).state();
        let body = unframe(&good).unwrap();
        assert_eq!(restore(body), None);
        assert_eq!(restore(&[body, &[0]].concat()), Some(StateError::Invalid));
        assert_eq!(restore(&body[..body.len() - 1]), Some(StateError::Invalid));
        // The orderly tag is the body's last byte for a TPM that never ran.
        let mut tag = body.to_vec();
        *tag.last_mut().unwrap() = 3;
        assert_eq!(restore(&tag), Some(StateError::Invalid));
    }
}
