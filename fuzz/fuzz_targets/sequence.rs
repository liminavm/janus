// SPDX-License-Identifier: MIT OR Apache-2.0

//! A sequence of commands, platform resets and locality changes into one TPM, so a fault that
//! needs earlier state to reach is reachable. The input is a list of records: a control byte,
//! then for a command a 16-bit length and that many bytes.
//!
//! Control byte: 0 is `_TPM_Init`; 1 to 5 set the locality to 0 to 4; anything else is a
//! command.

#![no_main]

use janus::{Janus, Locality};
use janus_fuzz::{check_response, Fixed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut tpm = Janus::manufacture(Fixed);
    let mut locality = Locality::ZERO;
    let mut rest = data;
    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        match op {
            0 => tpm.init(),
            1..=5 => locality = Locality::new(op - 1).unwrap(),
            _ => {
                if rest.len() < 2 {
                    return;
                }
                let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
                let (cmd, tail) = rest[2..].split_at(n);
                rest = tail;
                check_response(&tpm.execute(locality, cmd));
            }
        }
    }
});
