// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behaviour the corpus never exercises because real guests get it right: authorization
//! failures, lockout, locality, and malformed session areas. Each expected code is the one the
//! TCG reference implementation returns for the same command.

use janus::{Janus, Locality, Platform};

struct Zero;

impl Platform for Zero {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
}

const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const OWNER: u32 = 0x4000_0001;
const LOCKOUT: u32 = 0x4000_000A;
const RS_PW: u32 = 0x4000_0009;

fn cmd(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&cc.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn tpm2b(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// One password session with `password`, as an authorization area.
fn password(password: &[u8]) -> Vec<u8> {
    session(RS_PW, &[], 0, password)
}

fn session(handle: u32, nonce: &[u8], attrs: u8, hmac: &[u8]) -> Vec<u8> {
    let mut s = handle.to_be_bytes().to_vec();
    s.extend(tpm2b(nonce));
    s.push(attrs);
    s.extend(tpm2b(hmac));
    s
}

fn area(sessions: &[Vec<u8>]) -> Vec<u8> {
    let all: Vec<u8> = sessions.concat();
    let mut v = (all.len() as u32).to_be_bytes().to_vec();
    v.extend(all);
    v
}

fn change_auth(hierarchy: u32, current: &[u8], new: &[u8]) -> Vec<u8> {
    let mut body = hierarchy.to_be_bytes().to_vec();
    body.extend(area(&[password(current)]));
    body.extend(tpm2b(new));
    cmd(SESSIONS, 0x129, &body)
}

fn extend(pcr: u32) -> Vec<u8> {
    let mut body = pcr.to_be_bytes().to_vec();
    body.extend(area(&[password(b"")]));
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&0x000Bu16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    cmd(SESSIONS, 0x182, &body)
}

fn get_capability(cap: u32, property: u32, count: u32) -> Vec<u8> {
    let mut body = cap.to_be_bytes().to_vec();
    body.extend_from_slice(&property.to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body
}

fn started() -> Janus<Zero> {
    let mut tpm = Janus::manufacture(Zero);
    tpm.init();
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x144, &[0, 0]));
    assert_eq!(rc(&r), 0);
    tpm
}

fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

fn run(tpm: &mut Janus<Zero>, c: &[u8]) -> u32 {
    rc(&tpm.execute(Locality::ZERO, c))
}

#[test]
fn a_wrong_hierarchy_password_is_bad_auth_on_the_session() {
    let mut tpm = started();
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"", b"secret")), 0);
    // TPM_RC_BAD_AUTH on session 1: owner authorization is exempt from lockout.
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"wrong", b"x")), 0x9A2);
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"", b"x")), 0x9A2);
    // Trailing zeros are not part of a password.
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"secret\0\0", b"next")), 0);
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"next", b"")), 0);
}

#[test]
fn a_wrong_lockout_password_locks_lockout_authorization() {
    let mut tpm = started();
    assert_eq!(run(&mut tpm, &change_auth(LOCKOUT, b"", b"lock")), 0);
    // TPM_RC_AUTH_FAIL on session 1, then TPM_RC_LOCKOUT even with the right password.
    assert_eq!(run(&mut tpm, &change_auth(LOCKOUT, b"wrong", b"x")), 0x98E);
    assert_eq!(run(&mut tpm, &change_auth(LOCKOUT, b"lock", b"x")), 0x921);
}

#[test]
fn the_platform_authorization_lasts_until_the_next_startup() {
    let mut tpm = started();
    const PLATFORM: u32 = 0x4000_000C;
    assert_eq!(run(&mut tpm, &change_auth(PLATFORM, b"", b"plat")), 0);
    assert_eq!(run(&mut tpm, &change_auth(PLATFORM, b"", b"x")), 0x9A2);
    tpm.init();
    assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x144, &[0, 0])), 0);
    assert_eq!(run(&mut tpm, &change_auth(PLATFORM, b"", b"x")), 0);
}

#[test]
fn a_pcr_extends_only_from_its_localities() {
    let mut tpm = started();
    // PCR 17 is extendable from localities 2, 3 and 4 only: TPM_RC_LOCALITY.
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &extend(17))), 0x907);
    assert_eq!(rc(&tpm.execute(Locality::new(4).unwrap(), &extend(17))), 0);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &extend(0))), 0);
    // TPM_RH_NULL: nothing to extend, and success.
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &extend(0x4000_0007))), 0);
    // A handle that is not a PCR: TPM_RC_VALUE on handle 1.
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &extend(24))), 0x184);
}

#[test]
fn malformed_session_areas_are_refused_with_the_reference_codes() {
    let mut tpm = started();
    let mut body = OWNER.to_be_bytes().to_vec();
    // An authorization area too small for any session: TPM_RC_SIZE, no position.
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x129, &body)), 0x095);

    // A password session with a nonce: TPM_RC_NONCE on session 1.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(area(&[session(RS_PW, b"n", 0, b"")]));
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x129, &body)), 0x98F);

    // A password session asking for parameter encryption: TPM_RC_ATTRIBUTES on session 1.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(area(&[session(RS_PW, b"", 0x20, b"")]));
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x129, &body)), 0x982);

    // An HMAC session that is not loaded: TPM_RC_REFERENCE_S0.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(area(&[session(0x0200_0000, b"", 1, b"")]));
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x129, &body)), 0x918);

    // A second password session with nothing to authorize: TPM_RC_HANDLE on session 2.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(area(&[password(b""), password(b"")]));
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x129, &body)), 0xA8B);

    // No authorization area for a handle that needs one: TPM_RC_AUTH_MISSING.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(tpm2b(b""));
    assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x129, &body)), 0x125);

    // A password session on a command without an authorization handle: TPM_RC_HANDLE on 1.
    let mut body = area(&[password(b"")]);
    body.extend(get_capability(6, 0x100, 1));
    assert_eq!(run(&mut tpm, &cmd(SESSIONS, 0x17A, &body)), 0x98B);

    // Startup refuses an authorization area: TPM_RC_AUTH_CONTEXT.
    let mut fresh = Janus::manufacture(Zero);
    fresh.init();
    let mut body = area(&[password(b"")]);
    body.extend_from_slice(&[0, 0]);
    assert_eq!(run(&mut fresh, &cmd(SESSIONS, 0x144, &body)), 0x145);
}

#[test]
fn parameters_are_checked_after_authorization() {
    let mut tpm = started();
    // Bytes after the last parameter: TPM_RC_SIZE.
    let mut c = cmd(NO_SESSIONS, 0x17A, &get_capability(6, 0x100, 1));
    c.push(0);
    c[5] += 1;
    assert_eq!(run(&mut tpm, &c), 0x095);
    // An unknown capability: TPM_RC_VALUE on parameter 1.
    assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x17A, &get_capability(0x55, 0, 1))), 0x1C4);
    // A handle type GetCapability(HANDLES) does not know: TPM_RC_VALUE on parameter 2.
    assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x17A, &get_capability(1, 0x7F00_0000, 1))), 0x2C4);
    // A new authorization longer than any digest: TPM_RC_SIZE on parameter 1.
    assert_eq!(run(&mut tpm, &change_auth(OWNER, b"", &[1; 33])), 0x1D5);
}

#[test]
fn get_random_returns_at_most_one_digest() {
    let mut tpm = started();
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x17B, &[0, 64]));
    assert_eq!(rc(&r), 0);
    assert_eq!(u16::from_be_bytes([r[10], r[11]]), 32);
    assert_eq!(r.len(), 12 + 32);
}
