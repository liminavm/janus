// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command framing and response building.
//!
//! The header's `commandSize` and the length of the buffer the device delivered are two values
//! that must agree; they are reconciled here, once, and nothing after this sees either.

use crate::capability::MAX_COMMAND_SIZE;
use crate::cc::Cc;
use crate::rc::{At, Fmt0, Index, Rc};
use crate::wire::{Blame as _, Reader, Writer};

/// `TPM_ST_NO_SESSIONS` / `TPM_ST_SESSIONS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    NoSessions,
    Sessions,
}

impl Tag {
    const NO_SESSIONS: u16 = 0x8001;
    const SESSIONS: u16 = 0x8002;

    fn from_wire(t: u16) -> Option<Tag> {
        match t {
            Self::NO_SESSIONS => Some(Tag::NoSessions),
            Self::SESSIONS => Some(Tag::Sessions),
            _ => None,
        }
    }

    fn wire(self) -> u16 {
        match self {
            Tag::NoSessions => Self::NO_SESSIONS,
            Tag::Sessions => Self::SESSIONS,
        }
    }
}

/// A framed command: its header checked, its body not yet read.
pub struct Command<'a> {
    pub tag: Tag,
    pub cc: Cc,
    pub body: Reader<'a>,
}

/// Checks the header in the reference's order: the tag, then the size against the buffer and
/// the maximum, then whether the command is implemented.
pub fn frame(bytes: &[u8]) -> Result<Command<'_>, Rc> {
    let mut r = Reader::new(bytes);
    let tag = r.u16().map_err(Rc::bare)?;
    let tag = Tag::from_wire(tag).ok_or(Rc::BadTag)?;
    let size = r.u32().map_err(Rc::bare)?;
    if size as usize != bytes.len() || size > MAX_COMMAND_SIZE {
        return Err(Fmt0::CommandSize.into());
    }
    let code = r.u32().map_err(Rc::bare)?;
    let cc = Cc::from_code(code).ok_or(Rc::Fmt0(Fmt0::CommandCode))?;
    Ok(Command { tag, cc, body: r })
}

impl<'a> Command<'a> {
    /// The command's handle area: `n` raw handles, each a `TPM_RC_INSUFFICIENT` at its
    /// position if missing. The caller classifies them.
    pub fn handles<const N: usize>(&mut self) -> Result<[u32; N], Rc> {
        let mut out = [0u32; N];
        for (i, h) in out.iter_mut().enumerate() {
            let at = At::Handle(Index::new(i as u8 + 1).expect("at most seven handles"));
            *h = self.body.u32().at(at)?;
        }
        Ok(out)
    }

    /// The authorization area, for `TPM_ST_SESSIONS`; `None` for `TPM_ST_NO_SESSIONS`.
    pub fn area(&mut self) -> Option<&mut Reader<'a>> {
        match self.tag {
            Tag::Sessions => Some(&mut self.body),
            Tag::NoSessions => None,
        }
    }

    /// The parameter bytes: everything after the authorization area.
    pub fn params(&mut self) -> &'a [u8] {
        let n = self.body.remaining();
        self.body.bytes(n).expect("the remaining bytes are there")
    }
}

/// An error response: always `TPM_ST_NO_SESSIONS`, ten bytes.
pub fn error(rc: Rc) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(Tag::NO_SESSIONS);
    w.u32(10);
    w.u32(rc.code());
    w.into_vec()
}

/// A successful response: the command's tag, the response handle if the command has one, then
/// the parameters, with the parameter size and the authorization area when the command carried
/// sessions.
pub fn success(tag: Tag, handle: Option<u32>, params: &[u8], area: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(tag.wire());
    w.u32(0);
    w.u32(0);
    if let Some(h) = handle {
        w.u32(h);
    }
    if tag == Tag::Sessions {
        w.u32(u32::try_from(params.len()).expect("a response's parameters exceed 4 GiB"));
    }
    w.bytes(params);
    if tag == Tag::Sessions {
        w.bytes(area);
    }
    let size = u32::try_from(w.len()).expect("a response exceeds 4 GiB");
    w.patch_u32(2, size);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rc::Fmt1;

    fn rc(bytes: &[u8]) -> u32 {
        match frame(bytes) {
            Ok(_) => 0,
            Err(e) => e.code(),
        }
    }

    #[test]
    fn the_header_is_checked_in_the_reference_order() {
        // Too short to hold a tag.
        assert_eq!(rc(&[0x80]), Rc::bare(Fmt1::Insufficient).code());
        // A bad tag wins over a bad size.
        assert_eq!(rc(&[0x00, 0xC1, 0, 0, 0, 99, 0, 0, 0x01, 0x44]), 0x01E);
        // The size must be the buffer's length.
        assert_eq!(rc(&[0x80, 0x01, 0, 0, 0, 11, 0, 0, 0x01, 0x44]), 0x142);
        // Then the command must be implemented.
        assert_eq!(rc(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x23]), 0x143);
        assert_eq!(rc(&[0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0]), 0);
    }
}

/// The framing proof's unwind bound, which `cargo test` checks against the command table so a
/// new command cannot quietly outgrow it.
#[cfg(test)]
const FRAME_PROOF_UNWIND: usize = 44;

#[cfg(test)]
#[test]
fn the_frame_proof_unwinds_the_whole_command_table() {
    assert!(
        crate::cc::IMPLEMENTED.len() < FRAME_PROOF_UNWIND,
        "raise the unwind of a_frame_has_exactly_the_size_its_header_claims and FRAME_PROOF_UNWIND"
    );
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every buffer of up to 14 bytes: framing succeeds only if the header's size is the
    /// buffer's length, and the body is then exactly what follows the header.
    ///
    /// Framing looks the command code up in `cc::IMPLEMENTED`, so the bound must exceed its
    /// length; `the_frame_proof_unwinds_the_whole_command_table` holds it to that.
    #[kani::proof]
    #[kani::unwind(44)]
    fn a_frame_has_exactly_the_size_its_header_claims() {
        let data: [u8; 14] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 14);
        let bytes = &data[..len];
        if let Ok(c) = frame(bytes) {
            assert!(len >= 10);
            assert!(u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize == len);
            assert!(c.body.remaining() == len - 10);
        }
    }
}
