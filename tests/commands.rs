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

/// The kernel's null primary template: ECC P-256, restricted decrypt, AES-128-CFB, noDA.
const PARENT: [u8; 26] = [
    0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
];
const NULL: u32 = 0x4000_0007;

/// `TPM2_CreatePrimary(hierarchy)` with `template` (a `TPMT_PUBLIC`) and empty everything else.
fn create_primary(hierarchy: u32, template: &[u8]) -> Vec<u8> {
    let mut body = hierarchy.to_be_bytes().to_vec();
    body.extend(area(&[password(b"")]));
    body.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
    body.extend(tpm2b(template));
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    cmd(SESSIONS, 0x131, &body)
}

/// `template` with its `TPMA_OBJECT` replaced.
fn with_attributes(template: &[u8], attrs: u32) -> Vec<u8> {
    let mut t = template.to_vec();
    t[4..8].copy_from_slice(&attrs.to_be_bytes());
    t
}

fn context_save(handle: u32) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x162, &handle.to_be_bytes())
}

fn context_load(context: &[u8]) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x161, context)
}

fn flush(handle: u32) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x165, &handle.to_be_bytes())
}

fn shutdown(state: bool) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x145, &[0, state as u8])
}

fn startup(state: bool) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x144, &[0, state as u8])
}

/// `TPM2_StartAuthSession` with explicit fields.
fn start_session(
    tpm_key: u32,
    bind: u32,
    nonce: &[u8],
    salt: &[u8],
    kind: u8,
    symmetric: &[u8],
) -> Vec<u8> {
    let mut body = tpm_key.to_be_bytes().to_vec();
    body.extend_from_slice(&bind.to_be_bytes());
    body.extend(tpm2b(nonce));
    body.extend(tpm2b(salt));
    body.push(kind);
    body.extend_from_slice(symmetric);
    body.extend_from_slice(&0x000Bu16.to_be_bytes());
    cmd(NO_SESSIONS, 0x176, &body)
}

const SYM_NULL: [u8; 2] = [0x00, 0x10];

/// An unsalted, unbound HMAC session.
fn plain_session() -> Vec<u8> {
    start_session(NULL, NULL, &[0x33; 16], &[], 0, &SYM_NULL)
}

/// Runs `c` and returns its response, which must be a success.
fn ok(tpm: &mut Janus<Zero>, c: &[u8]) -> Vec<u8> {
    let r = tpm.execute(Locality::ZERO, c);
    assert_eq!(rc(&r), 0, "{c:02x?}");
    r
}

/// A saved context, as the parameters of the ContextSave response that carried it.
fn saved(tpm: &mut Janus<Zero>, handle: u32) -> Vec<u8> {
    ok(tpm, &context_save(handle))[10..].to_vec()
}

#[test]
fn create_primary_refuses_templates_in_the_reference_order() {
    let mut tpm = started();
    // fixedTPM without fixedParent: TPM_RC_ATTRIBUTES on inPublic (CreateChecks).
    assert_eq!(run(&mut tpm, &create_primary(NULL, &with_attributes(&PARENT, 0x0003_0462))), 0x2C2);
    // An unimplemented curve fails to unmarshal: TPM_RC_CURVE on inPublic.
    let mut p384 = PARENT.to_vec();
    p384[19] = 4;
    assert_eq!(run(&mut tpm, &create_primary(NULL, &p384)), 0x2E6);
    // A hierarchy handle that is not one: TPM_RC_VALUE on handle 1.
    assert_eq!(run(&mut tpm, &create_primary(LOCKOUT, &PARENT)), 0x184);
    // Three objects fill the transient slots; the fourth is TPM_RC_OBJECT_MEMORY.
    for _ in 0..3 {
        ok(&mut tpm, &create_primary(NULL, &PARENT));
    }
    assert_eq!(run(&mut tpm, &create_primary(NULL, &PARENT)), 0x902);
}

#[test]
fn context_commands_refuse_what_is_not_there() {
    let mut tpm = started();
    // Nothing in slot 0: TPM_RC_REFERENCE_H0. A PCR is not a context: TPM_RC_VALUE on handle 1.
    assert_eq!(run(&mut tpm, &context_save(0x8000_0000)), 0x910);
    assert_eq!(run(&mut tpm, &context_save(0)), 0x184);
    // FlushContext names its handle as a parameter: TPM_RC_HANDLE / TPM_RC_VALUE on it.
    assert_eq!(run(&mut tpm, &flush(0x8000_0000)), 0x1CB);
    assert_eq!(run(&mut tpm, &flush(0x0200_0000)), 0x1CB);
    assert_eq!(run(&mut tpm, &flush(OWNER)), 0x1C4);
}

#[test]
fn a_context_that_was_tampered_with_or_names_no_context_is_refused() {
    let mut tpm = started();
    ok(&mut tpm, &create_primary(NULL, &PARENT));
    let context = saved(&mut tpm, 0x8000_0000);
    // A flipped bit in the encrypted part: TPM_RC_INTEGRITY on the context.
    let mut tampered = context.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(run(&mut tpm, &context_load(&tampered)), 0x1DF);
    // A saved handle TPMI_DH_SAVED does not allow, here a persistent one: TPM_RC_VALUE.
    for bad in [0x8100_0000u32, 0x8000_0003, 0x4000_0001] {
        let mut wrong = context.clone();
        wrong[8..12].copy_from_slice(&bad.to_be_bytes());
        assert_eq!(run(&mut tpm, &context_load(&wrong)), 0x1C4, "saved handle {bad:#x}");
    }
    // The untouched context still loads.
    ok(&mut tpm, &context_load(&context));
}

#[test]
fn start_auth_session_checks_its_parameters_in_the_reference_order() {
    let mut tpm = started();
    // A nonce shorter than 16 bytes: TPM_RC_SIZE on nonceCaller.
    assert_eq!(run(&mut tpm, &start_session(NULL, NULL, &[1; 15], &[], 0, &SYM_NULL)), 0x1D5);
    // A salt with no key to decrypt it: TPM_RC_VALUE on encryptedSalt.
    assert_eq!(run(&mut tpm, &start_session(NULL, NULL, &[1; 16], &[1], 0, &SYM_NULL)), 0x2C4);
    // TPM_SE 2 does not exist: TPM_RC_VALUE on sessionType.
    assert_eq!(run(&mut tpm, &start_session(NULL, NULL, &[1; 16], &[], 2, &SYM_NULL)), 0x3C4);
    // AES-128 in OFB: TPM_RC_MODE on symmetric.
    let ofb = [0x00, 0x06, 0x00, 0x80, 0x00, 0x41];
    assert_eq!(run(&mut tpm, &start_session(NULL, NULL, &[1; 16], &[], 0, &ofb)), 0x4C9);
    // A key that does not decrypt: TPM_RC_ATTRIBUTES on tpmKey.
    let signer = [
        0x00, 0x23, 0x00, 0x0B, 0x00, 0x04, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
        0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    ];
    let r = ok(&mut tpm, &create_primary(NULL, &signer));
    let key = u32::from_be_bytes(r[10..14].try_into().unwrap());
    assert_eq!(run(&mut tpm, &start_session(key, NULL, &[1; 16], &[1; 68], 0, &SYM_NULL)), 0x182);
    // A loaded key that is not there any more: TPM_RC_REFERENCE_H0.
    ok(&mut tpm, &flush(key));
    assert_eq!(run(&mut tpm, &start_session(key, NULL, &[1; 16], &[1; 68], 0, &SYM_NULL)), 0x910);
}

/// Shutdown(STATE) and _TPM_Init, then the Startup that makes the next one a Resume, a Restart
/// or a Reset.
fn power_cycle(tpm: &mut Janus<Zero>, shutdown_state: bool, startup_state: bool) {
    ok(tpm, &shutdown(shutdown_state));
    tpm.init();
    ok(tpm, &startup(startup_state));
}

#[test]
fn saved_contexts_outlive_a_resume_and_a_restart_but_not_a_reset() {
    for (shutdown_state, startup_state, loads) in
        [(true, true, true), (true, false, true), (false, false, false)]
    {
        let mut tpm = started();
        ok(&mut tpm, &create_primary(NULL, &PARENT));
        let object = saved(&mut tpm, 0x8000_0000);
        let r = ok(&mut tpm, &plain_session());
        let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
        let session = saved(&mut tpm, handle);
        power_cycle(&mut tpm, shutdown_state, startup_state);
        let expected = if loads { 0 } else { 0x1DF };
        let what = (shutdown_state, startup_state);
        assert_eq!(run(&mut tpm, &context_load(&object)), expected, "object, {what:?}");
        assert_eq!(run(&mut tpm, &context_load(&session)), expected, "session, {what:?}");
    }
}

#[test]
fn an_st_clear_objects_context_dies_at_a_restart() {
    let mut tpm = started();
    // PARENT with stClear.
    ok(&mut tpm, &create_primary(NULL, &with_attributes(&PARENT, 0x0003_0476)));
    let object = saved(&mut tpm, 0x8000_0000);
    power_cycle(&mut tpm, true, true);
    ok(&mut tpm, &context_load(&object));
    ok(&mut tpm, &flush(0x8000_0000));
    power_cycle(&mut tpm, true, false);
    assert_eq!(run(&mut tpm, &context_load(&object)), 0x1DF);
}

#[test]
fn saving_a_context_after_shutdown_state_makes_the_resume_a_reset() {
    let mut tpm = started();
    let r = ok(&mut tpm, &plain_session());
    let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
    ok(&mut tpm, &shutdown(true));
    // ContextSave changes what Shutdown saved (`RETURN_IF_ORDERLY`).
    saved(&mut tpm, handle);
    tpm.init();
    assert_eq!(run(&mut tpm, &startup(true)), 0x1C4);
    ok(&mut tpm, &startup(false));
}
