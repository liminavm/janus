// SPDX-License-Identifier: MIT OR Apache-2.0

//! A snapshot's body, in a valid frame, into `Janus::resume`. Refusing it is fine; a panic is
//! not. A body it accepts must snapshot back to exactly the same bytes, save a state file that
//! restores, and answer commands as it stands, then start again after a `_TPM_Init`.

#![no_main]

use janus::{Janus, Locality};
use janus_fuzz::{Fixed, STARTUP, check_response, snapshot_file};
use libfuzzer_sys::fuzz_target;

fn capability(property: u32) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A];
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&property.to_be_bytes());
    v.extend_from_slice(&64u32.to_be_bytes());
    v
}

fuzz_target!(|body: &[u8]| {
    let file = snapshot_file(body);
    let Ok(mut tpm) = Janus::resume(Fixed::new().0, &file) else { return };
    assert_eq!(&tpm.snapshot()[..], &file[..], "a resumed TPM snapshots back differently");
    assert!(Janus::restore(Fixed::new().0, &tpm.state()).is_ok(), "its state does not restore");
    for property in [0x0100_0000, 0x0200_0000, 0x0300_0000, 0x8000_0000, 0x8100_0000] {
        check_response(&tpm.execute(Locality::ZERO, &capability(property)));
    }
    tpm.init();
    check_response(&tpm.execute(Locality::ZERO, &STARTUP));
});
