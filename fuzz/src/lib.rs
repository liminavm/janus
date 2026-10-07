// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the fuzz targets share: a deterministic platform and the response invariants every
//! answer must keep, whatever the command was.

use janus::Platform;

pub struct Fixed;

impl Platform for Fixed {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0x5A);
    }
}

/// `TPM2_Startup(CLEAR)`.
pub const STARTUP: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0];

/// A response is a well-formed frame: a known tag, a size field equal to its length, and, when
/// it is an error, exactly the ten-byte header.
pub fn check_response(rsp: &[u8]) {
    assert!(rsp.len() >= 10, "a response shorter than its header");
    let tag = u16::from_be_bytes([rsp[0], rsp[1]]);
    assert!(tag == 0x8001 || tag == 0x8002, "response tag {tag:#x}");
    let size = u32::from_be_bytes(rsp[2..6].try_into().unwrap());
    assert_eq!(size as usize, rsp.len(), "the size field disagrees with the response");
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    if rc != 0 {
        assert_eq!(rsp.len(), 10, "an error response carries a body");
        assert_eq!(tag, 0x8001, "an error response with a session tag");
    }
    assert!(rsp.len() <= 4096, "a response larger than MAX_RESPONSE_SIZE");
}
