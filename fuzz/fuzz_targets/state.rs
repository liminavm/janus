// SPDX-License-Identifier: MIT OR Apache-2.0

//! A state file's body, in a valid frame, into `Janus::restore`. Refusing it is fine; a panic
//! is not. A body it accepts must save back to exactly the same file, and the TPM it makes must
//! start, both ways, and answer like any other.

#![no_main]

use janus::{Janus, Locality};
use janus_fuzz::{Fixed, STARTUP, check_response, state_file};
use libfuzzer_sys::fuzz_target;

/// `TPM2_Startup(STATE)`.
const RESUME: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 1];

fn capability(property: u32) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A];
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&property.to_be_bytes());
    v.extend_from_slice(&64u32.to_be_bytes());
    v
}

fuzz_target!(|body: &[u8]| {
    let file = state_file(body);
    let Ok(mut tpm) = Janus::restore(Fixed::new().0, &file) else { return };
    assert_eq!(&tpm.state()[..], &file[..], "a restored state saves back differently");
    for startup in [RESUME, STARTUP] {
        check_response(&tpm.execute(Locality::ZERO, &startup));
        for property in [0x0100_0000, 0x0200_0000, 0x8100_0000] {
            check_response(&tpm.execute(Locality::ZERO, &capability(property)));
        }
        tpm.init();
    }
});
