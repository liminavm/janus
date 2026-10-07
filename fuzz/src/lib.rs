// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the fuzz targets share: a deterministic platform and the response invariants every
//! answer must keep, whatever the command was.

use janus::{Janus, Locality, Platform};

pub struct Fixed;

impl Platform for Fixed {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0x5A);
    }
    fn now_ms(&mut self) -> u64 {
        0
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

/// The kernel's null primary template: ECC P-256, restricted decrypt, AES-128-CFB.
const PARENT: [u8; 26] = [
    0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
];

fn command(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&cc.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn run(tpm: &mut Janus<Fixed>, cmd: &[u8]) -> Vec<u8> {
    let r = tpm.execute(Locality::ZERO, cmd);
    assert_eq!(&r[6..10], &[0; 4], "preparing the TPM failed: {cmd:02x?}");
    r
}

/// A started TPM holding what the context and session paths need to be reachable: a primary
/// key at 0x80000000, an HMAC session at 0x02000000, and, saved and out of memory, another
/// primary key and another session. Returns the TPM and the two saved `TPMS_CONTEXT`s, which
/// are the same on every run because [`Fixed`] is.
pub fn prepared() -> (Janus<Fixed>, Vec<Vec<u8>>) {
    let mut tpm = Janus::manufacture(Fixed);
    tpm.init();
    run(&mut tpm, &STARTUP);
    let mut create = 0x4000_0007u32.to_be_bytes().to_vec();
    create.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
    create.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
    create.extend_from_slice(&(PARENT.len() as u16).to_be_bytes());
    create.extend_from_slice(&PARENT);
    create.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let create = command(0x8002, 0x131, &create);
    let mut session = 0x4000_0007u32.to_be_bytes().to_vec();
    session.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    session.extend_from_slice(&[0, 16]);
    session.extend_from_slice(&[0x33; 16]);
    session.extend_from_slice(&[0, 0, 0, 0x00, 0x10, 0x00, 0x0B]);
    let session = command(0x8001, 0x176, &session);
    let save = |h: u32| command(0x8001, 0x162, &h.to_be_bytes());
    let flush = |h: u32| command(0x8001, 0x165, &h.to_be_bytes());
    run(&mut tpm, &create);
    run(&mut tpm, &create);
    let object = run(&mut tpm, &save(0x8000_0001))[10..].to_vec();
    run(&mut tpm, &flush(0x8000_0001));
    run(&mut tpm, &session);
    run(&mut tpm, &session);
    let saved_session = run(&mut tpm, &save(0x0200_0001))[10..].to_vec();
    (tpm, vec![object, saved_session])
}

/// Runs a record stream (see the `sequence` target) into `tpm`, checking every response.
pub fn run_records(tpm: &mut Janus<Fixed>, data: &[u8]) {
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
}

/// A ContextLoad of `context`, as one record.
pub fn context_load_record(context: &[u8]) -> Vec<u8> {
    let cmd = command(0x8001, 0x161, context);
    let mut r = vec![0xFF];
    r.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
    r.extend_from_slice(&cmd);
    r
}
