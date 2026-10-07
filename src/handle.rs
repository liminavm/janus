// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handles (`TPM_HANDLE`, Part 2 §7).
//!
//! A handle is a `u32` whose top byte says what kind of thing it names. Every interface type
//! that takes a handle (`TPMI_DH_PCR`, `TPMI_RH_HIERARCHY_AUTH`, …) accepts only some kinds, and
//! the reference checks that at unmarshal. So does this: each interface type is a function
//! from the raw `u32` to a type that can only hold what that interface accepts, and a handler
//! receives the type, never the `u32`.

use crate::pcr::PcrIndex;

/// `TPM_HT`, the top byte of a handle.
pub mod ht {
    pub const PCR: u8 = 0x00;
    pub const NV_INDEX: u8 = 0x01;
    pub const HMAC_SESSION: u8 = 0x02;
    pub const POLICY_SESSION: u8 = 0x03;
    pub const PERMANENT: u8 = 0x40;
    pub const TRANSIENT: u8 = 0x80;
    pub const PERSISTENT: u8 = 0x81;
}

/// `TPM_RH` / `TPM_RS` permanent handles the engine names.
pub mod rh {
    pub const OWNER: u32 = 0x4000_0001;
    pub const NULL: u32 = 0x4000_0007;
    pub const PW: u32 = 0x4000_0009;
    pub const LOCKOUT: u32 = 0x4000_000A;
    pub const ENDORSEMENT: u32 = 0x4000_000B;
    pub const PLATFORM: u32 = 0x4000_000C;
}

pub const fn handle_type(h: u32) -> u8 {
    (h >> 24) as u8
}

/// A hierarchy whose authorization value `TPM2_HierarchyChangeAuth` can change
/// (`TPMI_RH_HIERARCHY_AUTH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HierarchyAuth {
    Owner,
    Endorsement,
    Platform,
    Lockout,
}

impl HierarchyAuth {
    /// `TPMI_RH_HIERARCHY_AUTH`: any other value is `TPM_RC_VALUE`.
    pub const fn from_handle(h: u32) -> Option<HierarchyAuth> {
        match h {
            rh::OWNER => Some(HierarchyAuth::Owner),
            rh::ENDORSEMENT => Some(HierarchyAuth::Endorsement),
            rh::PLATFORM => Some(HierarchyAuth::Platform),
            rh::LOCKOUT => Some(HierarchyAuth::Lockout),
            _ => None,
        }
    }
}

/// The target of `TPM2_PCR_Extend` (`TPMI_DH_PCR+`): a PCR, or `TPM_RH_NULL`, for which the
/// command does nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcrOrNull {
    Pcr(PcrIndex),
    Null,
}

impl PcrOrNull {
    pub fn from_handle(h: u32) -> Option<PcrOrNull> {
        if h == rh::NULL {
            return Some(PcrOrNull::Null);
        }
        PcrIndex::from_handle(h).map(PcrOrNull::Pcr)
    }
}

/// A session handle in an authorization area (`TPMI_SH_AUTH_SESSION+`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthSessionHandle {
    /// `TPM_RS_PW`: a password, carried in the clear in the HMAC field.
    Password,
    Hmac(u32),
    Policy(u32),
}

impl AuthSessionHandle {
    pub const fn from_handle(h: u32) -> Option<AuthSessionHandle> {
        if h == rh::PW {
            return Some(AuthSessionHandle::Password);
        }
        match handle_type(h) {
            ht::HMAC_SESSION => Some(AuthSessionHandle::Hmac(h)),
            ht::POLICY_SESSION => Some(AuthSessionHandle::Policy(h)),
            _ => None,
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// TPMI_RH_HIERARCHY_AUTH accepts exactly the four hierarchy handles.
    #[kani::proof]
    fn hierarchy_auth_accepts_exactly_four_handles() {
        let h: u32 = kani::any();
        let ok = HierarchyAuth::from_handle(h).is_some();
        assert!(ok == matches!(h, rh::OWNER | rh::ENDORSEMENT | rh::PLATFORM | rh::LOCKOUT));
    }

    /// TPMI_DH_PCR+ accepts exactly the implemented PCRs and TPM_RH_NULL.
    #[kani::proof]
    fn pcr_or_null_accepts_exactly_the_pcrs_and_null() {
        let h: u32 = kani::any();
        match PcrOrNull::from_handle(h) {
            Some(PcrOrNull::Null) => {
                assert!(h == rh::NULL);
            }
            Some(PcrOrNull::Pcr(p)) => {
                assert!(h < crate::pcr::PCR_COUNT as u32);
                assert!(p.get() as u32 == h);
            }
            None => {
                assert!(h != rh::NULL && h >= crate::pcr::PCR_COUNT as u32);
            }
        }
    }

    /// TPMI_SH_AUTH_SESSION+ accepts TPM_RS_PW and the two session types, nothing else.
    #[kani::proof]
    fn auth_session_handles_are_classified_by_type() {
        let h: u32 = kani::any();
        match AuthSessionHandle::from_handle(h) {
            Some(AuthSessionHandle::Password) => {
                assert!(h == rh::PW);
            }
            Some(AuthSessionHandle::Hmac(x)) => {
                assert!(x == h && handle_type(h) == ht::HMAC_SESSION);
            }
            Some(AuthSessionHandle::Policy(x)) => {
                assert!(x == h && handle_type(h) == ht::POLICY_SESSION);
            }
            None => {
                assert!(
                    h != rh::PW
                        && handle_type(h) != ht::HMAC_SESSION
                        && handle_type(h) != ht::POLICY_SESSION
                );
            }
        }
    }
}
