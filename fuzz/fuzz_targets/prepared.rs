// SPDX-License-Identifier: MIT OR Apache-2.0

//! Records, as `sequence` takes them, into a TPM that already holds a key, a session and two
//! saved contexts ([`janus_fuzz::prepared`]): the object, session and context paths are
//! reachable from the first command instead of only after the fuzzer rebuilds that state.

#![no_main]

use janus_fuzz::{prepared, run_records};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (mut tpm, _) = prepared();
    run_records(&mut tpm, data);
});
