// SPDX-License-Identifier: MIT OR Apache-2.0

//! One command into a started TPM: no panic, and a well-formed response.

#![no_main]

use janus::{Janus, Locality};
use janus_fuzz::{Fixed, STARTUP, check_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut tpm = Janus::manufacture(Fixed::new().0);
    tpm.init();
    check_response(&tpm.execute(Locality::ZERO, &STARTUP));
    check_response(&tpm.execute(Locality::ZERO, data));
});
