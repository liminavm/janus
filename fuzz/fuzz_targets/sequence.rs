// SPDX-License-Identifier: MIT OR Apache-2.0

//! A sequence of commands, platform resets and locality changes into one TPM, so a fault that
//! needs earlier state to reach is reachable. The input is a list of records: a control byte,
//! then for a command a 16-bit length and that many bytes.
//!
//! Control byte: 0 is `_TPM_Init`; 1 to 5 set the locality to 0 to 4; anything else is a
//! command.

#![no_main]

use janus::Janus;
use janus_fuzz::{Fixed, run_records};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut tpm = Janus::manufacture(Fixed);
    run_records(&mut tpm, data);
});
