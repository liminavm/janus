// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command codes (`TPM_CC`) and what the engine knows about each implemented command.

/// An implemented command. A `TPM_CC` outside this enum is `TPM_RC_COMMAND_CODE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cc {
    HierarchyChangeAuth,
    CreatePrimary,
    SelfTest,
    Startup,
    Shutdown,
    Create,
    Load,
    RsaDecrypt,
    Sign,
    Unseal,
    ContextLoad,
    ContextSave,
    FlushContext,
    PolicyAuthValue,
    PolicyCommandCode,
    ReadPublic,
    StartAuthSession,
    EccParameters,
    GetCapability,
    GetRandom,
    Hash,
    PcrRead,
    PolicyPcr,
    PolicyRestart,
    PcrExtend,
    PolicyGetDigest,
    TestParms,
    PolicyPassword,
}

/// The implemented commands in `TPM_CC` order, which is the order `TPM_CAP_COMMANDS` lists them.
pub const IMPLEMENTED: [Cc; 28] = [
    Cc::HierarchyChangeAuth,
    Cc::CreatePrimary,
    Cc::SelfTest,
    Cc::Startup,
    Cc::Shutdown,
    Cc::Create,
    Cc::Load,
    Cc::RsaDecrypt,
    Cc::Sign,
    Cc::Unseal,
    Cc::ContextLoad,
    Cc::ContextSave,
    Cc::FlushContext,
    Cc::PolicyAuthValue,
    Cc::PolicyCommandCode,
    Cc::ReadPublic,
    Cc::StartAuthSession,
    Cc::EccParameters,
    Cc::GetCapability,
    Cc::GetRandom,
    Cc::Hash,
    Cc::PcrRead,
    Cc::PolicyPcr,
    Cc::PolicyRestart,
    Cc::PcrExtend,
    Cc::PolicyGetDigest,
    Cc::TestParms,
    Cc::PolicyPassword,
];

/// How a command uses its handles and sessions: the parts of `TPMA_CC` and of the reference's
/// command attribute table (`CommandAttributeData.h`) the dispatcher acts on.
#[derive(Clone, Copy, Debug)]
pub struct Attributes {
    /// May write NV (`TPMA_CC.nv`).
    pub nv: bool,
    /// Flushes any transient object in its handle area (`TPMA_CC.flushed`).
    pub flushed: bool,
    /// Handles in the command's handle area (`TPMA_CC.cHandles`).
    pub handles: u8,
    /// How many of those, from the first, need authorization.
    pub auth_handles: u8,
    /// A handle in the response (`TPMA_CC.rHandle`).
    pub response_handle: bool,
    /// The command refuses an authorization area (`TPM_ST_SESSIONS` is `TPM_RC_AUTH_CONTEXT`).
    pub no_sessions: bool,
    /// Its first parameter is a `TPM2B` a session may encrypt (`DECRYPT_2`).
    pub decrypt: bool,
    /// Its first response parameter is a `TPM2B` a session may encrypt (`ENCRYPT_2`).
    pub encrypt: bool,
}

const NONE: Attributes = Attributes {
    nv: false,
    flushed: false,
    handles: 0,
    auth_handles: 0,
    response_handle: false,
    no_sessions: false,
    decrypt: false,
    encrypt: false,
};

impl Cc {
    pub const fn code(self) -> u32 {
        match self {
            Cc::HierarchyChangeAuth => 0x129,
            Cc::CreatePrimary => 0x131,
            Cc::SelfTest => 0x143,
            Cc::Startup => 0x144,
            Cc::Shutdown => 0x145,
            Cc::Create => 0x153,
            Cc::Load => 0x157,
            Cc::RsaDecrypt => 0x159,
            Cc::Sign => 0x15D,
            Cc::Unseal => 0x15E,
            Cc::ContextLoad => 0x161,
            Cc::ContextSave => 0x162,
            Cc::FlushContext => 0x165,
            Cc::PolicyAuthValue => 0x16B,
            Cc::PolicyCommandCode => 0x16C,
            Cc::ReadPublic => 0x173,
            Cc::StartAuthSession => 0x176,
            Cc::EccParameters => 0x178,
            Cc::GetCapability => 0x17A,
            Cc::GetRandom => 0x17B,
            Cc::Hash => 0x17D,
            Cc::PcrRead => 0x17E,
            Cc::PolicyPcr => 0x17F,
            Cc::PolicyRestart => 0x180,
            Cc::PcrExtend => 0x182,
            Cc::PolicyGetDigest => 0x189,
            Cc::TestParms => 0x18A,
            Cc::PolicyPassword => 0x18C,
        }
    }

    pub fn from_code(code: u32) -> Option<Cc> {
        IMPLEMENTED.into_iter().find(|c| c.code() == code)
    }

    /// From the reference's `CommandAttributeData.h`.
    pub const fn attributes(self) -> Attributes {
        match self {
            Cc::HierarchyChangeAuth => {
                Attributes { nv: true, handles: 1, auth_handles: 1, decrypt: true, ..NONE }
            }
            Cc::CreatePrimary => Attributes {
                handles: 1,
                auth_handles: 1,
                response_handle: true,
                decrypt: true,
                encrypt: true,
                ..NONE
            },
            Cc::SelfTest | Cc::Shutdown => Attributes { nv: true, ..NONE },
            Cc::Startup => Attributes { nv: true, no_sessions: true, ..NONE },
            Cc::ContextLoad => Attributes { response_handle: true, no_sessions: true, ..NONE },
            Cc::ContextSave => Attributes { handles: 1, no_sessions: true, ..NONE },
            Cc::FlushContext => Attributes { no_sessions: true, ..NONE },
            Cc::ReadPublic => Attributes { handles: 1, encrypt: true, ..NONE },
            Cc::StartAuthSession => Attributes {
                handles: 2,
                response_handle: true,
                decrypt: true,
                encrypt: true,
                ..NONE
            },
            Cc::Create => {
                Attributes { handles: 1, auth_handles: 1, decrypt: true, encrypt: true, ..NONE }
            }
            Cc::Load => Attributes {
                handles: 1,
                auth_handles: 1,
                response_handle: true,
                decrypt: true,
                encrypt: true,
                ..NONE
            },
            Cc::RsaDecrypt => {
                Attributes { handles: 1, auth_handles: 1, decrypt: true, encrypt: true, ..NONE }
            }
            Cc::Sign => Attributes { handles: 1, auth_handles: 1, decrypt: true, ..NONE },
            Cc::Unseal => Attributes { handles: 1, auth_handles: 1, encrypt: true, ..NONE },
            Cc::PolicyPcr => Attributes { handles: 1, decrypt: true, ..NONE },
            Cc::PolicyAuthValue
            | Cc::PolicyPassword
            | Cc::PolicyCommandCode
            | Cc::PolicyRestart => Attributes { handles: 1, ..NONE },
            Cc::PolicyGetDigest => Attributes { handles: 1, encrypt: true, ..NONE },
            Cc::Hash => Attributes { decrypt: true, encrypt: true, ..NONE },
            Cc::TestParms | Cc::EccParameters => NONE,
            Cc::GetCapability | Cc::PcrRead => NONE,
            Cc::GetRandom => Attributes { encrypt: true, ..NONE },
            Cc::PcrExtend => Attributes { nv: true, handles: 1, auth_handles: 1, ..NONE },
        }
    }

    /// `TPMA_CC` as `TPM_CAP_COMMANDS` reports it.
    pub const fn tpma_cc(self) -> u32 {
        let a = self.attributes();
        (self.code() & 0xFFFF)
            | ((a.nv as u32) << 22)
            | ((a.flushed as u32) << 24)
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
        // TPMA_CC_INITIALIZER(0x0176, 0, 0, 0, 0, 2, 1, 0, 0)
        assert_eq!(Cc::StartAuthSession.tpma_cc(), 0x1400_0176);
        // TPMA_CC_INITIALIZER(0x0131, 0, 0, 0, 0, 1, 1, 0, 0)
        assert_eq!(Cc::CreatePrimary.tpma_cc(), 0x1200_0131);
    }
}
