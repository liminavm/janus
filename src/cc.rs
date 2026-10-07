// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command codes (`TPM_CC`) and what the engine knows about each implemented command.

/// An implemented command. A `TPM_CC` outside this enum is `TPM_RC_COMMAND_CODE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cc {
    HierarchyChangeAuth,
    SelfTest,
    Startup,
    Shutdown,
    GetCapability,
    GetRandom,
    PcrRead,
    PcrExtend,
}

/// The implemented commands in `TPM_CC` order, which is the order `TPM_CAP_COMMANDS` lists them.
pub const IMPLEMENTED: [Cc; 8] = [
    Cc::HierarchyChangeAuth,
    Cc::SelfTest,
    Cc::Startup,
    Cc::Shutdown,
    Cc::GetCapability,
    Cc::GetRandom,
    Cc::PcrRead,
    Cc::PcrExtend,
];

/// How a command uses its handles and sessions: the parts of `TPMA_CC` and of the reference's
/// command attribute table the dispatcher acts on.
#[derive(Clone, Copy, Debug)]
pub struct Attributes {
    /// May write NV (`TPMA_CC.nv`).
    pub nv: bool,
    /// Handles in the command's handle area (`TPMA_CC.cHandles`).
    pub handles: u8,
    /// How many of those, from the first, need authorization.
    pub auth_handles: u8,
    /// A handle in the response (`TPMA_CC.rHandle`).
    pub response_handle: bool,
    /// The command refuses an authorization area (`TPM_ST_SESSIONS` is `TPM_RC_AUTH_CONTEXT`).
    pub no_sessions: bool,
}

const fn attrs(nv: bool, handles: u8, auth_handles: u8, no_sessions: bool) -> Attributes {
    Attributes { nv, handles, auth_handles, response_handle: false, no_sessions }
}

impl Cc {
    pub const fn code(self) -> u32 {
        match self {
            Cc::HierarchyChangeAuth => 0x129,
            Cc::SelfTest => 0x143,
            Cc::Startup => 0x144,
            Cc::Shutdown => 0x145,
            Cc::GetCapability => 0x17A,
            Cc::GetRandom => 0x17B,
            Cc::PcrRead => 0x17E,
            Cc::PcrExtend => 0x182,
        }
    }

    pub fn from_code(code: u32) -> Option<Cc> {
        IMPLEMENTED.into_iter().find(|c| c.code() == code)
    }

    /// From the reference's `CommandAttributeData.h`.
    pub const fn attributes(self) -> Attributes {
        match self {
            Cc::HierarchyChangeAuth => attrs(true, 1, 1, false),
            Cc::SelfTest => attrs(true, 0, 0, false),
            Cc::Startup => attrs(true, 0, 0, true),
            Cc::Shutdown => attrs(true, 0, 0, false),
            Cc::GetCapability => attrs(false, 0, 0, false),
            Cc::GetRandom => attrs(false, 0, 0, false),
            Cc::PcrRead => attrs(false, 0, 0, false),
            Cc::PcrExtend => attrs(true, 1, 1, false),
        }
    }

    /// `TPMA_CC` as `TPM_CAP_COMMANDS` reports it.
    pub const fn tpma_cc(self) -> u32 {
        let a = self.attributes();
        (self.code() & 0xFFFF)
            | ((a.nv as u32) << 22)
            | ((a.handles as u32) << 25)
            | ((a.response_handle as u32) << 28)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implemented_is_sorted_and_complete() {
        assert!(IMPLEMENTED.windows(2).all(|w| w[0].code() < w[1].code()));
        for c in IMPLEMENTED {
            assert_eq!(Cc::from_code(c.code()), Some(c));
        }
    }

    #[test]
    fn tpma_cc_matches_the_reference() {
        // TPMA_CC_INITIALIZER(0x0182, 0, 1, 0, 0, 1, 0, 0, 0)
        assert_eq!(Cc::PcrExtend.tpma_cc(), 0x0240_0182);
        // TPMA_CC_INITIALIZER(0x017A, 0, 0, 0, 0, 0, 0, 0, 0)
        assert_eq!(Cc::GetCapability.tpma_cc(), 0x0000_017A);
    }
}
