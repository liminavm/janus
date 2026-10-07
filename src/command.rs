// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command framing and response building.
//!
//! The header's `commandSize` and the length of the buffer the device delivered are two values
//! that must agree; they are reconciled here, once, and nothing after this sees either.

use crate::capability::MAX_COMMAND_SIZE;
use crate::cc::Cc;
use crate::rc::{Fmt0, Rc};
use crate::session::AuthArea;
use crate::wire::{Reader, Writer};

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
    /// The authorization area, which follows the handles, with its sessions bound to the
    /// handles that need authorization. A `TPM_ST_NO_SESSIONS` command has none, which is
    /// `TPM_RC_AUTH_MISSING` if it has such a handle.
    pub fn auth_area(&mut self) -> Result<AuthArea<'a>, Rc> {
        let attrs = self.cc.attributes();
        let mut area = match self.tag {
            Tag::NoSessions => AuthArea::none(),
            Tag::Sessions => AuthArea::read(&mut self.body, !attrs.no_sessions)?,
        };
        area.bind(usize::from(attrs.auth_handles))?;
        Ok(area)
    }

    /// The parameters have been read: anything left over is `TPM_RC_SIZE`.
    pub fn finish(self) -> Result<(), Rc> {
        self.body.finish().map_err(Rc::bare)
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

/// A successful response: the command's tag, then the parameters, with the parameter size and
/// the authorization area when the command carried sessions.
pub fn success(tag: Tag, params: Writer, auth: &AuthArea<'_>) -> Vec<u8> {
    auth.finish();
    let mut w = Writer::new();
    w.u16(tag.wire());
    w.u32(0);
    w.u32(0);
    let params = params.into_vec();
    if tag == Tag::Sessions {
        w.u32(u32::try_from(params.len()).expect("a response's parameters exceed 4 GiB"));
    }
    w.bytes(&params);
    if tag == Tag::Sessions {
        auth.write_response(&mut w);
    }
    let size = w.len();
    let size = u32::try_from(size).expect("a response exceeds 4 GiB");
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

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every buffer of up to 14 bytes: framing succeeds only if the header's size is the
    /// buffer's length, and the body is then exactly what follows the header.
    #[kani::proof]
    #[kani::unwind(16)]
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
