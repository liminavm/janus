// SPDX-License-Identifier: MIT OR Apache-2.0

//! Response codes (`TPM_RC`, Part 2 §6.6).
//!
//! A response code is a bit field. Bit 7 picks format 1, which carries the position of what
//! failed: a handle, a session or a parameter, and its 1-based index. Bit 11 in format 0
//! marks a warning. Building one by ORing constants invites a code with a format-1 error and no
//! position, or a session index of 9, or a warning bit on a format-1 code. Here a code is built
//! from its parts, and [`Rc::code`] is the only place the bits are assembled.

use core::fmt;

/// A failed command's response code. Success is not one of these: it is `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rc {
    /// `TPM_RC_BAD_TAG` (`0x01E`), the one code below `RC_VER1`, kept for TPM 1.2 compatibility.
    BadTag,
    Fmt0(Fmt0),
    Warn(Warn),
    Fmt1(Fmt1, Option<At>),
}

/// Format-0 errors (`RC_VER1 + n`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Fmt0 {
    Initialize = 0x000,
    Failure = 0x001,
    Sequence = 0x003,
    Private = 0x00B,
    Hmac = 0x019,
    Disabled = 0x020,
    Exclusive = 0x021,
    AuthType = 0x024,
    AuthMissing = 0x025,
    Policy = 0x026,
    Pcr = 0x027,
    PcrChanged = 0x028,
    Upgrade = 0x02D,
    TooManyContexts = 0x02E,
    AuthUnavailable = 0x02F,
    Reboot = 0x030,
    Unbalanced = 0x031,
    CommandSize = 0x042,
    CommandCode = 0x043,
    AuthSize = 0x044,
    AuthContext = 0x045,
    NvRange = 0x046,
    NvSize = 0x047,
    NvLocked = 0x048,
    NvAuthorization = 0x049,
    NvUninitialized = 0x04A,
    NvSpace = 0x04B,
    NvDefined = 0x04C,
    BadContext = 0x050,
    CpHash = 0x051,
    Parent = 0x052,
    NeedsTest = 0x053,
    NoResult = 0x054,
    Sensitive = 0x055,
    ReadOnly = 0x056,
}

/// Format-1 errors (`RC_FMT1 + n`), which may name the handle, session or parameter at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Fmt1 {
    Asymmetric = 0x001,
    Attributes = 0x002,
    Hash = 0x003,
    Value = 0x004,
    Hierarchy = 0x005,
    KeySize = 0x007,
    Mgf = 0x008,
    Mode = 0x009,
    Type = 0x00A,
    Handle = 0x00B,
    Kdf = 0x00C,
    Range = 0x00D,
    AuthFail = 0x00E,
    Nonce = 0x00F,
    Pp = 0x010,
    Scheme = 0x012,
    Size = 0x015,
    Symmetric = 0x016,
    Tag = 0x017,
    Selector = 0x018,
    Insufficient = 0x01A,
    Signature = 0x01B,
    Key = 0x01C,
    PolicyFail = 0x01D,
    Integrity = 0x01F,
    Ticket = 0x020,
    ReservedBits = 0x021,
    BadAuth = 0x022,
    Expired = 0x023,
    PolicyCc = 0x024,
    Binding = 0x025,
    Curve = 0x026,
    EccPoint = 0x027,
}

/// Warnings (`RC_WARN + n`): the command may succeed if retried, perhaps after the caller makes
/// room or loads something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warn {
    ContextGap,
    ObjectMemory,
    SessionMemory,
    Memory,
    SessionHandles,
    ObjectHandles,
    Locality,
    Yielded,
    Canceled,
    Testing,
    /// `TPM_RC_REFERENCE_Hn`: the handle at this 0-based position does not reference a loaded
    /// object or session.
    ReferenceH(Slot),
    /// `TPM_RC_REFERENCE_Sn`: the session at this 0-based position is not loaded.
    ReferenceS(Slot),
    NvRate,
    Lockout,
    Retry,
    NvUnavailable,
}

/// A 0-based handle or session slot for the `REFERENCE` warnings, 0 to 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot(u8);

impl Slot {
    pub const fn new(n: u8) -> Option<Slot> {
        if n <= 6 { Some(Slot(n)) } else { None }
    }
}

/// Which handle, session or parameter a format-1 error is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// Handles are numbered 1 to 7.
    Handle(Index<7>),
    /// Sessions are numbered 1 to 7.
    Session(Index<7>),
    /// Parameters are numbered 1 to 15.
    Param(Index<15>),
}

/// A 1-based position no larger than `MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index<const MAX: u8>(u8);

impl<const MAX: u8> Index<MAX> {
    /// `None` outside `1..=MAX`. A `const` caller that names a position statically gets a
    /// build failure instead, through [`Index::of`].
    pub const fn new(n: u8) -> Option<Self> {
        if n >= 1 && n <= MAX { Some(Index(n)) } else { None }
    }

    /// A position known when the code is written. Out of range fails const evaluation.
    pub const fn of(n: u8) -> Self {
        match Self::new(n) {
            Some(i) => i,
            None => panic!("response code position out of range"),
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl At {
    pub const fn param(n: u8) -> At {
        At::Param(Index::of(n))
    }
    pub const fn handle(n: u8) -> At {
        At::Handle(Index::of(n))
    }
    pub const fn session(n: u8) -> At {
        At::Session(Index::of(n))
    }
}

const RC_VER1: u32 = 0x100;
const RC_FMT1: u32 = 0x080;
const RC_WARN: u32 = 0x900;
const RC_P: u32 = 0x040;
const RC_S: u32 = 0x800;

impl Warn {
    const fn offset(self) -> u32 {
        match self {
            Warn::ContextGap => 0x001,
            Warn::ObjectMemory => 0x002,
            Warn::SessionMemory => 0x003,
            Warn::Memory => 0x004,
            Warn::SessionHandles => 0x005,
            Warn::ObjectHandles => 0x006,
            Warn::Locality => 0x007,
            Warn::Yielded => 0x008,
            Warn::Canceled => 0x009,
            Warn::Testing => 0x00A,
            Warn::ReferenceH(s) => 0x010 + s.0 as u32,
            Warn::ReferenceS(s) => 0x018 + s.0 as u32,
            Warn::NvRate => 0x020,
            Warn::Lockout => 0x021,
            Warn::Retry => 0x022,
            Warn::NvUnavailable => 0x023,
        }
    }
}

impl Rc {
    /// A format-1 error with no position (the reference returns these for errors in the
    /// command framing, such as an authorization area of the wrong size).
    pub const fn bare(e: Fmt1) -> Rc {
        Rc::Fmt1(e, None)
    }

    /// The code on the wire.
    pub const fn code(self) -> u32 {
        match self {
            Rc::BadTag => 0x01E,
            Rc::Fmt0(e) => RC_VER1 + e as u32,
            Rc::Warn(w) => RC_WARN + w.offset(),
            Rc::Fmt1(e, at) => {
                let pos = match at {
                    None => 0,
                    Some(At::Handle(i)) => (i.0 as u32) << 8,
                    Some(At::Session(i)) => RC_S | ((i.0 as u32) << 8),
                    Some(At::Param(i)) => RC_P | ((i.0 as u32) << 8),
                };
                RC_FMT1 + e as u32 + pos
            }
        }
    }
}

impl fmt::Display for Rc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (0x{:03x})", self, self.code())
    }
}

impl From<Fmt0> for Rc {
    fn from(e: Fmt0) -> Rc {
        Rc::Fmt0(e)
    }
}

impl From<Warn> for Rc {
    fn from(w: Warn) -> Rc {
        Rc::Warn(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_specification() {
        assert_eq!(Rc::Fmt0(Fmt0::Initialize).code(), 0x100);
        assert_eq!(Rc::Fmt0(Fmt0::CommandSize).code(), 0x142);
        assert_eq!(Rc::Fmt0(Fmt0::CommandCode).code(), 0x143);
        assert_eq!(Rc::BadTag.code(), 0x01E);
        // TPM_RC_VALUE on parameter 1, as swtpm answers a TestParms it cannot meet.
        assert_eq!(Rc::Fmt1(Fmt1::Value, Some(At::param(1))).code(), 0x1c4);
        assert_eq!(Rc::Fmt1(Fmt1::Hash, Some(At::param(1))).code(), 0x1c3);
        assert_eq!(Rc::Fmt1(Fmt1::BadAuth, Some(At::session(1))).code(), 0x9a2);
        assert_eq!(Rc::Fmt1(Fmt1::Value, Some(At::handle(1))).code(), 0x184);
        assert_eq!(Rc::Warn(Warn::ReferenceH(Slot::new(0).unwrap())).code(), 0x910);
        assert_eq!(Rc::Warn(Warn::ReferenceS(Slot::new(0).unwrap())).code(), 0x918);
        assert_eq!(Rc::bare(Fmt1::Size).code(), 0x095);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_at() -> Option<At> {
        let n: u8 = kani::any();
        match kani::any::<u8>() % 4 {
            0 => None,
            1 => Some(At::Handle(Index::new(n)?)),
            2 => Some(At::Session(Index::new(n)?)),
            _ => Some(At::Param(Index::new(n)?)),
        }
    }

    /// Every positioned format-1 code keeps bit 7 set, keeps the warning bit pattern away from
    /// handle positions, and decodes back to the position it was built from.
    #[kani::proof]
    fn format_one_positions_round_trip() {
        let at = any_at();
        let code = Rc::Fmt1(Fmt1::Value, at).code();
        assert!(code & RC_FMT1 != 0);
        assert!(code & 0x03F == Fmt1::Value as u32);
        let n = ((code >> 8) & 0xF) as u8;
        match at {
            None => {
                assert!(code == RC_FMT1 + Fmt1::Value as u32);
            }
            Some(At::Handle(i)) => {
                assert!(code & (RC_P | RC_S) == 0);
                assert!(n == i.get() && n <= 7);
            }
            Some(At::Session(i)) => {
                assert!(code & RC_P == 0 && code & RC_S != 0);
                assert!((n & 7) == i.get());
            }
            Some(At::Param(i)) => {
                assert!(code & RC_P != 0);
                assert!(n == i.get());
            }
        }
    }

    /// Index::new accepts exactly 1..=MAX.
    #[kani::proof]
    fn index_accepts_exactly_its_range() {
        let n: u8 = kani::any();
        assert!(Index::<7>::new(n).is_some() == (1..=7).contains(&n));
        assert!(Index::<15>::new(n).is_some() == (1..=15).contains(&n));
    }
}
