// SPDX-License-Identifier: MIT OR Apache-2.0

//! `TPM2_GetCapability`.

use crate::alg::{HASHES, MAX_DIGEST};
use crate::cc::IMPLEMENTED;
use crate::context::{MAX_OBJECT_CONTEXT, MAX_SESSION_CONTEXT};
use crate::handle::{ht, rh};
use crate::object::{MAX_LOADED_OBJECTS, MAX_PERSISTENT_OBJECTS};
use crate::pcr::{self, PCR_COUNT, PCR_SELECT_SIZE, Selection};
use crate::rc::{At, Fmt1, Rc};
use crate::session::{CONTEXT_GAP_MAX, MAX_ACTIVE_SESSIONS, MAX_LOADED_SESSIONS};
use crate::wire::Writer;

/// `TPM_CAP` values.
mod cap {
    pub const ALGS: u32 = 0;
    pub const HANDLES: u32 = 1;
    pub const COMMANDS: u32 = 2;
    pub const PP_COMMANDS: u32 = 3;
    pub const AUDIT_COMMANDS: u32 = 4;
    pub const PCRS: u32 = 5;
    pub const TPM_PROPERTIES: u32 = 6;
    pub const PCR_PROPERTIES: u32 = 7;
    pub const ECC_CURVES: u32 = 8;
    pub const AUTH_POLICIES: u32 = 9;
    pub const ACT: u32 = 10;
}

/// The capability buffer is 1024 bytes (`MAX_CAP_BUFFER`); the counts below are how many of
/// each entry fit after the capability and count fields.
const MAX_CAP_BUFFER: u32 = 1024;
const MAX_CAP_DATA: u32 = MAX_CAP_BUFFER - 8;
const MAX_CAP_ALGS: u32 = MAX_CAP_DATA / 6;
const MAX_CAP_HANDLES: u32 = MAX_CAP_DATA / 4;
const MAX_CAP_CC: u32 = MAX_CAP_DATA / 4;
const MAX_TPM_PROPERTIES: u32 = MAX_CAP_DATA / 8;

const PT_GROUP: u32 = 0x100;
const PT_FIXED: u32 = PT_GROUP;
const PT_VAR: u32 = PT_GROUP * 2;

/// The largest command and response this TPM takes, which clients size their buffers from.
pub const MAX_COMMAND_SIZE: u32 = 4096;
pub const MAX_RESPONSE_SIZE: u32 = 4096;

/// Facts about the running TPM that the variable properties and the handle lists report.
pub struct Variable {
    pub owner_auth_set: bool,
    pub endorsement_auth_set: bool,
    pub lockout_auth_set: bool,
    pub orderly: bool,
    /// Loaded transient objects' handles, in order.
    pub transient: Vec<u32>,
    /// Persistent objects' handles, in order.
    pub persistent: Vec<u32>,
    /// Loaded sessions' handles, in order.
    pub loaded_sessions: Vec<u32>,
    /// Saved sessions' handles, in order.
    pub saved_sessions: Vec<u32>,
}

const fn chars(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// The fixed properties, in `TPM_PT` order. Values for things the engine does not have yet
/// (contexts, NV) are the bounds those features will be built to.
const FIXED: &[(u32, u32)] = &[
    (0x100, chars(b"2.0\0")),               // FAMILY_INDICATOR
    (0x101, 0),                             // LEVEL
    (0x102, 183),                           // REVISION: Library specification 1.83,
    (0x103, 25),                            // DAY_OF_YEAR  dated 25 January 2024
    (0x104, 2024),                          // YEAR
    (0x105, chars(b"JNUS")),                // MANUFACTURER
    (0x106, chars(b"janu")),                // VENDOR_STRING_1
    (0x107, chars(b"s\0\0\0")),             // VENDOR_STRING_2
    (0x108, 0),                             // VENDOR_STRING_3
    (0x109, 0),                             // VENDOR_STRING_4
    (0x10A, 0),                             // VENDOR_TPM_TYPE
    (0x10B, 0x0001_0000),                   // FIRMWARE_VERSION_1
    (0x10C, 0),                             // FIRMWARE_VERSION_2
    (0x10D, 1024),                          // INPUT_BUFFER
    (0x10E, MAX_LOADED_OBJECTS as u32),     // HR_TRANSIENT_MIN
    (0x10F, MAX_PERSISTENT_OBJECTS as u32), // HR_PERSISTENT_MIN
    (0x110, MAX_LOADED_SESSIONS as u32),    // HR_LOADED_MIN
    (0x111, MAX_ACTIVE_SESSIONS as u32),    // ACTIVE_SESSIONS_MAX
    (0x112, PCR_COUNT as u32),              // PCR_COUNT
    (0x113, PCR_SELECT_SIZE as u32),        // PCR_SELECT_MIN
    (0x114, CONTEXT_GAP_MAX as u32),        // CONTEXT_GAP_MAX
    (0x116, 0),                             // NV_COUNTERS_MAX
    (0x117, 2048),                          // NV_INDEX_MAX
    (0x118, 0x6),                           // MEMORY: objects copied to RAM, shared RAM
    (0x119, 1 << 12),                       // CLOCK_UPDATE
    (0x11A, crate::alg::id::SHA256 as u32), // CONTEXT_HASH
    (0x11B, crate::alg::id::AES as u32),    // CONTEXT_SYM
    (0x11C, 128),                           // CONTEXT_SYM_SIZE: AES-128
    (0x11D, 255),                           // ORDERLY_COUNT
    (0x11E, MAX_COMMAND_SIZE),              // MAX_COMMAND_SIZE
    (0x11F, MAX_RESPONSE_SIZE),             // MAX_RESPONSE_SIZE
    (0x120, MAX_DIGEST as u32),             // MAX_DIGEST
    (0x121, MAX_OBJECT_CONTEXT as u32),     // MAX_OBJECT_CONTEXT
    (0x122, MAX_SESSION_CONTEXT as u32),    // MAX_SESSION_CONTEXT
    (0x123, 1),                             // PS_FAMILY_INDICATOR: PC Client
    (0x124, 0),                             // PS_LEVEL
    (0x125, 0x106),                         // PS_REVISION
    (0x126, 25),                            // PS_DAY_OF_YEAR
    (0x127, 2024),                          // PS_YEAR
    (0x128, 0),                             // SPLIT_MAX
    (0x129, IMPLEMENTED.len() as u32),      // TOTAL_COMMANDS
    (0x12A, IMPLEMENTED.len() as u32),      // LIBRARY_COMMANDS
    (0x12B, 0),                             // VENDOR_COMMANDS
    (0x12C, 1024),                          // NV_BUFFER_MAX
    (0x12D, 0),                             // MODES
    (0x12E, MAX_CAP_BUFFER),                // MAX_CAP_BUFFER
];

fn variable(v: &Variable) -> Vec<(u32, u32)> {
    let permanent = (v.owner_auth_set as u32)
        | ((v.endorsement_auth_set as u32) << 1)
        | ((v.lockout_auth_set as u32) << 2);
    // phEnable, shEnable, ehEnable, phEnableNV: no command can clear them yet.
    let startup_clear = 0xF | ((v.orderly as u32) << 31);
    let loaded = v.loaded_sessions.len() as u32;
    let active = loaded + v.saved_sessions.len() as u32;
    let transient = v.transient.len() as u32;
    let persistent = v.persistent.len() as u32;
    vec![
        (0x200, permanent),                                  // PERMANENT
        (0x201, startup_clear),                              // STARTUP_CLEAR
        (0x202, 0),                                          // HR_NV_INDEX
        (0x203, loaded),                                     // HR_LOADED
        (0x204, MAX_LOADED_SESSIONS as u32 - loaded),        // HR_LOADED_AVAIL
        (0x205, active),                                     // HR_ACTIVE
        (0x206, MAX_ACTIVE_SESSIONS as u32 - active),        // HR_ACTIVE_AVAIL
        (0x207, MAX_LOADED_OBJECTS as u32 - transient),      // HR_TRANSIENT_AVAIL
        (0x208, persistent),                                 // HR_PERSISTENT
        (0x209, MAX_PERSISTENT_OBJECTS as u32 - persistent), // HR_PERSISTENT_AVAIL
        (0x20A, 0),                                          // NV_COUNTERS
        (0x20B, 0),                                          // NV_COUNTERS_AVAIL
        (0x20C, 0),                                          // ALGORITHM_SET
        (0x20D, 0),                                          // LOADED_CURVES
    ]
}

/// The permanent handles this TPM has, in order.
const PERMANENT: &[u32] =
    &[rh::OWNER, rh::NULL, rh::PW, rh::LOCKOUT, rh::ENDORSEMENT, rh::PLATFORM];

/// The algorithms `TPM_CAP_ALGS` lists, with their `TPMA_ALGORITHM`, in id order: every one a
/// client may name in a command janus implements, with the attributes the reference gives it.
///
/// `TPMA_ALGORITHM`: asymmetric 0x1, symmetric 0x2, hash 0x4, object 0x8, signing 0x100,
/// encrypting 0x200, method 0x400.
const ALGS: &[(u16, u32)] = &[
    (crate::alg::id::RSA, 0x9),
    (crate::alg::id::HMAC, 0x104),
    (crate::alg::id::AES, 0x2),
    (crate::alg::id::KEYEDHASH, 0x30C),
    (crate::alg::id::SHA256, 0x4),
    (crate::alg::id::NULL, 0x0),
    (crate::alg::id::RSASSA, 0x101),
    (crate::alg::id::RSAES, 0x201),
    (crate::alg::id::RSAPSS, 0x101),
    (crate::alg::id::OAEP, 0x201),
    (crate::alg::id::ECDSA, 0x101),
    (crate::alg::id::ECDH, 0x401),
    (crate::alg::id::ECC, 0x9),
    (crate::alg::id::SYMCIPHER, 0x8),
    (crate::alg::id::CFB, 0x202),
];

/// Answers `TPM2_GetCapability(capability, property, count)`.
pub fn get(
    capability: u32,
    property: u32,
    count: u32,
    v: &Variable,
    w: &mut Writer,
) -> Result<(), Rc> {
    match capability {
        cap::ALGS => {
            let list = ALGS.iter().filter(|(a, _)| u32::from(*a) >= property);
            emit(w, capability, count.min(MAX_CAP_ALGS), list, |w, (a, attrs)| {
                w.u16(*a);
                w.u32(*attrs);
            });
        }
        cap::HANDLES => {
            let from = |list: &[u32]| list.iter().copied().filter(|h| *h >= property).collect();
            let handles: Vec<u32> = match (property >> 24) as u8 {
                ht::PCR => (property..PCR_COUNT as u32).collect(),
                ht::PERMANENT => from(PERMANENT),
                ht::TRANSIENT => from(&v.transient),
                // TPM_HT_LOADED_SESSION and TPM_HT_SAVED_SESSION share the HMAC and policy
                // session handle types in this capability.
                ht::HMAC_SESSION => from(&v.loaded_sessions),
                ht::POLICY_SESSION => from(&v.saved_sessions),
                ht::PERSISTENT => from(&v.persistent),
                ht::NV_INDEX => Vec::new(),
                _ => return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(2)))),
            };
            emit(w, capability, count.min(MAX_CAP_HANDLES), handles.iter(), |w, h| w.u32(*h));
        }
        cap::COMMANDS => {
            let list = IMPLEMENTED.iter().filter(|c| c.code() >= property);
            emit(w, capability, count.min(MAX_CAP_CC), list, |w, c| w.u32(c.tpma_cc()));
        }
        cap::PP_COMMANDS | cap::AUDIT_COMMANDS => {
            emit(w, capability, 0, core::iter::empty::<u32>(), |w, c| w.u32(c));
        }
        cap::PCRS => {
            // The whole allocation, whatever property and count ask for.
            w.u8(0);
            w.u32(capability);
            let banks: Vec<Selection> = HASHES.iter().map(|h| Selection::all(*h)).collect();
            pcr::write_selection_list(w, &banks);
        }
        cap::TPM_PROPERTIES => {
            let props: Vec<(u32, u32)> = if property < PT_VAR {
                let start = property.max(PT_FIXED);
                FIXED.iter().copied().filter(|(t, _)| *t >= start).collect()
            } else if property < PT_VAR + PT_GROUP {
                variable(v).into_iter().filter(|(t, _)| *t >= property).collect()
            } else {
                Vec::new()
            };
            emit(w, capability, count.min(MAX_TPM_PROPERTIES), props.iter(), |w, (t, val)| {
                w.u32(*t);
                w.u32(*val);
            });
        }
        cap::ECC_CURVES => {
            let list =
                [crate::alg::curve::NIST_P256].into_iter().filter(|c| u32::from(*c) >= property);
            emit(w, capability, count.min(MAX_CAP_DATA / 2), list, |w, c| w.u16(c));
        }
        cap::PCR_PROPERTIES | cap::AUTH_POLICIES | cap::ACT => {
            emit(w, capability, 0, core::iter::empty::<u32>(), |w, c| w.u32(c));
        }
        _ => return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1)))),
    }
    Ok(())
}

/// `moreData`, the capability, then a counted list of at most `max` entries; `moreData` is YES
/// when the list was cut short.
fn emit<T>(
    w: &mut Writer,
    capability: u32,
    max: u32,
    entries: impl Iterator<Item = T>,
    mut each: impl FnMut(&mut Writer, T),
) {
    let entries: Vec<T> = entries.collect();
    let n = entries.len().min(max as usize);
    w.u8((entries.len() > n) as u8);
    w.u32(capability);
    w.u32(n as u32);
    for e in entries.into_iter().take(n) {
        each(w, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_properties_are_sorted_and_within_their_group() {
        assert!(FIXED.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(FIXED.iter().all(|(t, _)| (PT_FIXED..PT_VAR).contains(t)));
        assert!(FIXED.len() as u32 <= MAX_TPM_PROPERTIES);
    }

    #[test]
    fn permanent_handles_are_sorted() {
        assert!(PERMANENT.windows(2).all(|w| w[0] < w[1]));
    }
}
