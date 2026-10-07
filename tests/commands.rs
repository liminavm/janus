// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behaviour the corpus never exercises because real guests get it right: authorization
//! failures, lockout, locality, and malformed session areas. Each expected code is the one the
//! TCG reference implementation returns for the same command.

use janus::{Janus, Locality, Platform, SelfTests};

struct Zero;

impl Platform for Zero {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        0
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

/// swtpm's answer to `TPM2_ECC_Parameters(TPM_ECC_NIST_P256)`, from `tests/corpus/08-openssl`.
const P256_PARAMETERS: &str = "8001000000e300000000000301000020000b00100020ffffffff000000010000\
    00000000000000000000ffffffffffffffffffffffff0020ffffffff0000000100000000000000000000000\
    0fffffffffffffffffffffffc00205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27\
    d2604b00206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29600204fe342e2f\
    e1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50020ffffffff00000000ffffffffffff\
    ffffbce6faada7179e84f3b9cac2fc632551000101";

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn ecc_parameters_answers_as_swtpm_does() {
    let mut tpm = started();
    let r = ok(&mut tpm, &cmd(NO_SESSIONS, 0x178, &[0, 3]));
    assert_eq!(r, hex(P256_PARAMETERS));
    // Any other curve is TPM_RC_CURVE on the parameter.
    assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x178, &[0, 4])), 0x1E6);
}

#[test]
fn test_parms_accepts_what_janus_implements() {
    let mut tpm = started();
    // The corpus's own questions, which swtpm answered this way.
    for (parms, expected) in [
        ("0025000600800043", 0),             // SYMCIPHER, AES-128-CFB
        ("0023000600800043001000030010", 0), // ECC P-256 storage parameters
        ("00230010001000030010", 0),         // ECC P-256, nothing else
        ("000100100010100000000000", 0x1C4), // RSA-4096: TPM_RC_VALUE
    ] {
        assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x18A, &hex(parms))), expected, "{parms}");
    }
    // Where janus implements less than swtpm: RSA-1024 and -3072, and the ECC curves but
    // P-256, which swtpm accepts and janus refuses as the reference would refuse a curve or
    // key size it was built without.
    for (parms, expected) in [
        ("000100100010040000000000", 0x1C4),
        ("0001001000100c0000000000", 0x1C4),
        ("00230010001000010010", 0x1E6),
        ("00230010001000050010", 0x1E6),
    ] {
        assert_eq!(run(&mut tpm, &cmd(NO_SESSIONS, 0x18A, &hex(parms))), expected, "{parms}");
    }
}

/// `TPM2_Hash(data, SHA-256, hierarchy)`; returns the digest, and the ticket's hierarchy and
/// HMAC.
fn hash(tpm: &mut Janus<Counting>, data: &[u8], hierarchy: u32) -> (Vec<u8>, u32, Vec<u8>) {
    let body = [tpm2b(data), vec![0, 0x0B], hierarchy.to_be_bytes().to_vec()].concat();
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x17D, &body));
    assert_eq!(rc(&r), 0);
    assert_eq!(r[44..46], [0x80, 0x24], "TPM_ST_HASHCHECK");
    let h = u32::from_be_bytes(r[46..50].try_into().unwrap());
    (r[12..44].to_vec(), h, r[52..].to_vec())
}

/// Randomness that differs from draw to draw, so each hierarchy gets its own proof.
struct Counting(u8);

impl Platform for Counting {
    fn fill_random(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
    }

    fn now_ms(&mut self) -> u64 {
        0
    }
}

#[test]
fn hash_tickets_only_what_the_tpm_could_not_have_produced() {
    use sha2::Digest as _;
    let mut tpm = Janus::manufacture(Counting(0));
    tpm.init();
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x144, &[0, 0]))), 0);
    let (digest, h, ticket) = hash(&mut tpm, b"message", OWNER);
    assert_eq!(digest, sha2::Sha256::digest(b"message").to_vec());
    assert_eq!((h, ticket.len()), (OWNER, 32));
    // The same message under the same hierarchy gets the same ticket; another hierarchy's
    // proof gives another.
    assert_eq!(hash(&mut tpm, b"message", OWNER).2, ticket);
    assert_ne!(hash(&mut tpm, b"message", 0x4000_000B).2, ticket);
    // A NULL ticket under the NULL hierarchy, and for data that starts like something the TPM
    // signs (TPM_GENERATED_VALUE), so it cannot be passed off as an attestation.
    let (_, h, ticket) = hash(&mut tpm, b"message", NULL);
    assert_eq!((h, ticket.len()), (NULL, 0));
    let (_, h, ticket) = hash(&mut tpm, b"\xffTCGmessage", OWNER);
    assert_eq!((h, ticket.len()), (NULL, 0));
    // Shorter than TPM_GENERATED_VALUE is safe.
    assert_eq!(hash(&mut tpm, b"\xffTC", OWNER).2.len(), 32);
}

#[test]
fn policy_commands_refuse_what_is_not_a_loaded_policy_session() {
    use sha2::Digest as _;
    let mut tpm = started();
    let hmac = u32::from_be_bytes(ok(&mut tpm, &plain_session())[10..14].try_into().unwrap());
    let get_digest = |h: u32| cmd(NO_SESSIONS, 0x189, &h.to_be_bytes());
    // An HMAC session is not a TPMI_SH_POLICY: TPM_RC_VALUE on the handle.
    assert_eq!(run(&mut tpm, &get_digest(hmac)), 0x184);
    // A policy handle with nothing loaded under it: TPM_RC_REFERENCE_H0.
    assert_eq!(run(&mut tpm, &get_digest(0x0300_0001)), 0x910);

    let policy = start_session(NULL, NULL, &[0x33; 16], &[], 1, &SYM_NULL);
    let p = u32::from_be_bytes(ok(&mut tpm, &policy)[10..14].try_into().unwrap());
    let command_code =
        |code: u32| cmd(NO_SESSIONS, 0x16C, &[p.to_be_bytes(), code.to_be_bytes()].concat());
    // A command janus does not implement: TPM_RC_POLICY_CC on the parameter.
    assert_eq!(run(&mut tpm, &command_code(0x14F)), 0x1E4);
    assert_eq!(ok(&mut tpm, &get_digest(p))[12..], [0; 32], "a refused update changes nothing");
    ok(&mut tpm, &command_code(0x15E));
    let expected = sha2::Sha256::digest(
        [&[0; 32][..], &0x16Cu32.to_be_bytes(), &0x15Eu32.to_be_bytes()].concat(),
    );
    assert_eq!(ok(&mut tpm, &get_digest(p))[12..], expected[..]);
    // A second, different command code: TPM_RC_VALUE on the parameter.
    assert_eq!(run(&mut tpm, &command_code(0x17B)), 0x1C4);
}

/// A platform whose clock the test sets.
struct Clocked(std::rc::Rc<std::cell::Cell<u64>>);

impl Platform for Clocked {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }

    fn now_ms(&mut self) -> u64 {
        self.0.get()
    }
}

/// TPM2_ReadClock's TPMS_TIME_INFO: time, clock, resetCount, restartCount, safe.
fn read_clock(tpm: &mut Janus<Clocked>) -> (u64, u64, u32, u32, u8) {
    let rsp = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x181, &[]));
    assert_eq!(rc(&rsp), 0, "ReadClock");
    assert_eq!(rsp.len(), 35);
    let u64_at = |i: usize| u64::from_be_bytes(rsp[i..i + 8].try_into().unwrap());
    let u32_at = |i: usize| u32::from_be_bytes(rsp[i..i + 4].try_into().unwrap());
    (u64_at(10), u64_at(18), u32_at(26), u32_at(30), rsp[34])
}

#[test]
fn the_clock_runs_while_the_tpm_does_and_time_since_init() {
    let now = std::rc::Rc::new(std::cell::Cell::new(5_000u64));
    let mut tpm = Janus::manufacture(Clocked(now.clone()));
    tpm.init();
    // Before Startup: TPM_RC_INITIALIZE, as swtpm answered the firmware (boot.jsonl).
    let rsp = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x181, &[]));
    assert_eq!(rc(&rsp), 0x100);
    now.set(5_100);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup(false))), 0);
    now.set(5_250);
    // A new TPM is manufactured orderly (`TPM_Manufacture`): its first clock is safe.
    assert_eq!(read_clock(&mut tpm), (250, 250, 1, 0, 1));

    // An orderly Shutdown(STATE) and a Resume: time restarts, the clock goes on, one restart.
    let power = |tpm: &mut Janus<Clocked>, state: bool, at: u64| {
        assert_eq!(rc(&tpm.execute(Locality::ZERO, &shutdown(state))), 0);
        now.set(at);
        tpm.init();
        assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup(state))), 0);
    };
    power(&mut tpm, true, 9_000);
    now.set(9_040);
    assert_eq!(read_clock(&mut tpm), (40, 4_040, 1, 1, 1));
    // A platform clock reading earlier than the last counts as no time, nor does the way back.
    now.set(8_000);
    assert_eq!(read_clock(&mut tpm), (40, 4_040, 1, 1, 1));
    now.set(9_040);
    assert_eq!(read_clock(&mut tpm), (40, 4_040, 1, 1, 1));
    // A Restart counts as a restart too.
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &shutdown(true))), 0);
    tpm.init();
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup(false))), 0);
    assert_eq!(read_clock(&mut tpm), (0, 4_040, 1, 2, 1));
    // A Reset after an orderly Shutdown(CLEAR) zeroes restartCount and counts a reset.
    power(&mut tpm, false, 9_040);
    assert_eq!(read_clock(&mut tpm), (0, 4_040, 2, 0, 1));
    // A Startup with no orderly shutdown before it makes the clock unsafe.
    tpm.init();
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup(false))), 0);
    assert_eq!(read_clock(&mut tpm), (0, 4_040, 3, 0, 0));
    // It becomes safe again when it crosses a save boundary (2^22 ms), and stays so.
    now.set(9_040 + (1 << 22));
    assert_eq!(read_clock(&mut tpm).4, 1);
    power(&mut tpm, false, 9_040 + (1 << 22));
    assert_eq!(read_clock(&mut tpm).4, 1);
}

/// `TPM_CAP_ALGS` lists every algorithm a client may name in a command janus implements, with
/// the `TPMA_ALGORITHM` swtpm reports for it (the corpus's GetCapability answers); like the
/// reference, not `TPM_ALG_NULL`.
#[test]
fn the_algorithm_list_is_every_algorithm_janus_implements() {
    let mut tpm = started();
    let rsp = ok(&mut tpm, &cmd(NO_SESSIONS, 0x17A, &get_capability(0, 0, 64)));
    let n = u32::from_be_bytes(rsp[15..19].try_into().unwrap()) as usize;
    let listed: Vec<(u16, u32)> = (0..n)
        .map(|i| {
            let e = &rsp[19 + 6 * i..25 + 6 * i];
            (u16::from_be_bytes([e[0], e[1]]), u32::from_be_bytes(e[2..6].try_into().unwrap()))
        })
        .collect();
    let expected = [
        (0x0001, 0x009), // RSA
        (0x0005, 0x104), // HMAC
        (0x0006, 0x002), // AES
        (0x0008, 0x30C), // KEYEDHASH
        (0x000B, 0x004), // SHA256
        (0x0014, 0x101), // RSASSA
        (0x0015, 0x201), // RSAES
        (0x0016, 0x101), // RSAPSS
        (0x0017, 0x201), // OAEP
        (0x0018, 0x101), // ECDSA
        (0x0019, 0x401), // ECDH
        (0x0023, 0x009), // ECC
        (0x0025, 0x008), // SYMCIPHER
        (0x0043, 0x202), // CFB
    ];
    assert_eq!(listed, expected);
}

/// Runs `c` on any platform and returns its response code.
fn exec<P: Platform>(tpm: &mut Janus<P>, c: &[u8]) -> u32 {
    rc(&tpm.execute(Locality::ZERO, c))
}

/// An NV index at `index` with the password `pin`, readable and writable under it or the
/// owner's, 8 bytes, protected from dictionary attacks unless `no_da`.
fn nv_define_pin(index: u32, pin: &[u8], no_da: bool) -> Vec<u8> {
    let attributes = 0x0006_0006u32 | if no_da { 1 << 25 } else { 0 };
    let public = [
        &index.to_be_bytes()[..],
        &0x000Bu16.to_be_bytes(),
        &attributes.to_be_bytes(),
        &tpm2b(&[]),
        &8u16.to_be_bytes(),
    ]
    .concat();
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend(area(&[password(b"")]));
    body.extend(tpm2b(pin));
    body.extend(tpm2b(&public));
    cmd(SESSIONS, 0x12A, &body)
}

/// TPM2_NV_Read of 8 bytes by `by` with `pw`. The index is never written, so an accepted
/// authorization answers TPM_RC_NV_UNINITIALIZED (0x14A).
fn nv_read_with(by: u32, index: u32, pw: &[u8]) -> Vec<u8> {
    let mut body = by.to_be_bytes().to_vec();
    body.extend_from_slice(&index.to_be_bytes());
    body.extend(area(&[password(pw)]));
    body.extend_from_slice(&8u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    cmd(SESSIONS, 0x14E, &body)
}

fn lock_reset(pw: &[u8]) -> Vec<u8> {
    let mut body = LOCKOUT.to_be_bytes().to_vec();
    body.extend(area(&[password(pw)]));
    cmd(SESSIONS, 0x139, &body)
}

fn da_parameters(handle: u32, pw: &[u8], max: u32, recovery: u32, lockout: u32) -> Vec<u8> {
    let mut body = handle.to_be_bytes().to_vec();
    body.extend(area(&[password(pw)]));
    for v in [max, recovery, lockout] {
        body.extend_from_slice(&v.to_be_bytes());
    }
    cmd(SESSIONS, 0x13A, &body)
}

/// TPM_PT_LOCKOUT_COUNTER through TPM_PT_LOCKOUT_RECOVERY, and TPMA_PERMANENT.inLockout.
fn da_state<P: Platform>(tpm: &mut Janus<P>) -> ([u32; 4], bool) {
    let rsp = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x17A, &get_capability(6, 0x20E, 4)));
    assert_eq!(rc(&rsp), 0);
    let u32_at = |i: usize| u32::from_be_bytes(rsp[i..i + 4].try_into().unwrap());
    assert_eq!(u32_at(15), 4);
    let mut values = [0; 4];
    for (k, v) in values.iter_mut().enumerate() {
        assert_eq!(u32_at(19 + 8 * k), 0x20E + k as u32);
        *v = u32_at(23 + 8 * k);
    }
    let rsp = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x17A, &get_capability(6, 0x200, 1)));
    let permanent = u32::from_be_bytes(rsp[23..27].try_into().unwrap());
    (values, permanent & 1 << 9 != 0)
}

fn clocked_started(at: u64) -> (Janus<Clocked>, std::rc::Rc<std::cell::Cell<u64>>) {
    let now = std::rc::Rc::new(std::cell::Cell::new(at));
    let mut tpm = Janus::manufacture(Clocked(now.clone()));
    tpm.init();
    assert_eq!(exec(&mut tpm, &startup(false)), 0);
    (tpm, now)
}

/// A protected entity's wrong password counts a failure (`IncrementLockout`); at `maxTries` (3)
/// every protected entity is locked out (`CheckLockedOut`), even with the right password, while
/// exempt ones are not; one failure heals per `recoveryTime` (1000 s) of `Time`
/// (`DASelfHeal`), and DictionaryAttackLockReset heals them all.
#[test]
fn protected_entities_lock_out_after_three_failures_and_heal_with_time() {
    let (mut tpm, now) = clocked_started(0);
    let index = 0x0150_0000;
    assert_eq!(exec(&mut tpm, &nv_define_pin(index, b"pin", false)), 0);
    let exempt = 0x0150_0001;
    assert_eq!(exec(&mut tpm, &nv_define_pin(exempt, b"pin", true)), 0);
    // A manufactured TPM starts orderly: nothing counted, the reference's defaults.
    assert_eq!(da_state(&mut tpm), ([0, 3, 1000, 1000], false));
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"pin")), 0x14A);
    // A noDA index's wrong password is TPM_RC_BAD_AUTH and counts nothing.
    assert_eq!(exec(&mut tpm, &nv_read_with(exempt, exempt, b"no")), 0x9A2);
    for n in 1..=3 {
        assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"no")), 0x98E, "failure {n}");
        assert_eq!(da_state(&mut tpm).0[0], n);
    }
    assert_eq!(da_state(&mut tpm), ([3, 3, 1000, 1000], true));
    // Locked out: TPM_RC_LOCKOUT before the password is even compared.
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"pin")), 0x921);
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"no")), 0x921);
    assert_eq!(da_state(&mut tpm).0[0], 3, "a refusal in lockout counts nothing");
    // The owner's authorization and a noDA index's are exempt.
    assert_eq!(exec(&mut tpm, &nv_read_with(OWNER, index, b"")), 0x14A);
    assert_eq!(exec(&mut tpm, &nv_read_with(exempt, exempt, b"pin")), 0x14A);
    // Time heals one failure per 1000 s since the last failure.
    now.set(999_999);
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"pin")), 0x921);
    now.set(1_000_000);
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"pin")), 0x14A);
    assert_eq!(da_state(&mut tpm), ([2, 3, 1000, 1000], false));
    now.set(2_500_000);
    assert_eq!(da_state(&mut tpm).0[0], 1);
    // DictionaryAttackLockReset under the lockout hierarchy clears the rest.
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0);
    assert_eq!(da_state(&mut tpm).0[0], 0);
    // A failure restarts the healing: it heals 1000 s after itself, not after the last heal.
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"no")), 0x98E);
    now.set(3_499_999);
    assert_eq!(da_state(&mut tpm).0[0], 1);
    now.set(3_500_000);
    assert_eq!(da_state(&mut tpm).0[0], 0);
}

/// A failed lockout authorization disables it (`lockOutAuthEnabled`) until `lockoutRecovery`
/// (1000 s) has passed; with `lockoutRecovery` 0, until the next Startup.
#[test]
fn a_failed_lockout_authorization_recovers_after_lockout_recovery() {
    let (mut tpm, now) = clocked_started(0);
    assert_eq!(exec(&mut tpm, &lock_reset(b"wrong")), 0x98E);
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0x921);
    // It counts nothing toward the protected entities' limit.
    assert_eq!(da_state(&mut tpm), ([0, 3, 1000, 1000], false));
    now.set(999_999);
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0x921);
    now.set(1_000_000);
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0);

    assert_eq!(exec(&mut tpm, &da_parameters(LOCKOUT, b"", 3, 1000, 0)), 0);
    assert_eq!(exec(&mut tpm, &lock_reset(b"wrong")), 0x98E);
    now.set(100_000_000);
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0x921);
    assert_eq!(exec(&mut tpm, &shutdown(false)), 0);
    tpm.init();
    assert_eq!(exec(&mut tpm, &startup(false)), 0);
    assert_eq!(exec(&mut tpm, &lock_reset(b"")), 0);
}

/// `DAStartup`: a Startup after no orderly shutdown counts a failure, since one may have gone
/// unrecorded, up to `maxTries`; an orderly one counts nothing.
#[test]
fn a_startup_after_no_orderly_shutdown_counts_a_failure() {
    let (mut tpm, _) = clocked_started(0);
    let restart = |tpm: &mut Janus<Clocked>, orderly: bool| {
        if orderly {
            assert_eq!(exec(tpm, &shutdown(false)), 0);
        }
        tpm.init();
        assert_eq!(exec(tpm, &startup(false)), 0);
        da_state(tpm).0[0]
    };
    assert_eq!(restart(&mut tpm, false), 1);
    assert_eq!(restart(&mut tpm, true), 1);
    assert_eq!(restart(&mut tpm, false), 2);
    assert_eq!(restart(&mut tpm, false), 3);
    assert_eq!(restart(&mut tpm, false), 3, "no further than maxTries");
    // The counter survives _TPM_Init, as the reference keeps it in NV.
    assert_eq!(da_state(&mut tpm), ([3, 3, 1000, 1000], true));
}

/// DictionaryAttackParameters sets the limit and both recovery times, under the lockout
/// hierarchy only; a `recoveryTime` of 0 turns the counter off (`IncrementLockout` still
/// answers TPM_RC_AUTH_FAIL).
#[test]
fn dictionary_attack_parameters_set_the_limits() {
    let (mut tpm, _) = clocked_started(0);
    // TPMI_RH_LOCKOUT: TPM_RC_VALUE on the handle for any other.
    assert_eq!(exec(&mut tpm, &da_parameters(OWNER, b"", 5, 10, 20)), 0x184);
    let mut reset = lock_reset(b"");
    reset[10..14].copy_from_slice(&OWNER.to_be_bytes());
    assert_eq!(exec(&mut tpm, &reset), 0x184);
    // A parameter missing: TPM_RC_INSUFFICIENT on it.
    let mut short = da_parameters(LOCKOUT, b"", 5, 10, 20);
    short.truncate(short.len() - 4);
    let size = (short.len() as u32).to_be_bytes();
    short[2..6].copy_from_slice(&size);
    assert_eq!(exec(&mut tpm, &short), 0x3DA);
    assert_eq!(exec(&mut tpm, &da_parameters(LOCKOUT, b"", 5, 10, 20)), 0);
    assert_eq!(da_state(&mut tpm), ([0, 5, 10, 20], false));

    let index = 0x0150_0000;
    assert_eq!(exec(&mut tpm, &nv_define_pin(index, b"pin", false)), 0);
    assert_eq!(exec(&mut tpm, &da_parameters(LOCKOUT, b"", 1, 0, 20)), 0);
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"no")), 0x98E);
    assert_eq!(da_state(&mut tpm), ([0, 1, 0, 20], false));
    assert_eq!(exec(&mut tpm, &nv_read_with(index, index, b"pin")), 0x14A);
}

/// A platform whose self-tests fail while its flag is set (`_plat__SetForceFailureMode`).
struct Faulty(std::rc::Rc<std::cell::Cell<bool>>);

impl Platform for Faulty {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
    fn self_tests(&mut self) -> SelfTests {
        if self.0.get() { SelfTests::Fail } else { SelfTests::Run }
    }
}

fn self_test(full: bool) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x143, &[full as u8])
}

fn get_test_result() -> Vec<u8> {
    cmd(NO_SESSIONS, 0x17C, &[])
}

/// GetTestResult in failure mode: twelve bytes of data, a failure location whose low half
/// names the family, `FATAL_ERROR_SELF_TEST`, then TPM_RC_FAILURE (`TpmFailureMode`).
fn failed_at(family: u32) -> Vec<u8> {
    let mut v = vec![0x80, 0x01, 0, 0, 0, 0x1C, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0];
    v.extend_from_slice(&family.to_be_bytes());
    v.extend_from_slice(&6u32.to_be_bytes());
    v.extend_from_slice(&0x101u32.to_be_bytes());
    v
}

const FAILURE: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01];

#[test]
fn self_tests_pass_and_get_test_result_reports_success() {
    let mut tpm = started();
    assert_eq!(run(&mut tpm, &self_test(true)), 0);
    assert_eq!(run(&mut tpm, &self_test(false)), 0);
    // CryptGetTestResult: no data, TPM_RC_SUCCESS.
    assert_eq!(
        tpm.execute(Locality::ZERO, &get_test_result()),
        [0x80, 0x01, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn a_failed_self_test_answers_only_get_test_result_and_properties_until_init() {
    let fail = std::rc::Rc::new(std::cell::Cell::new(false));
    let mut tpm = Janus::manufacture(Faulty(fail.clone()));
    tpm.init();
    assert_eq!(exec(&mut tpm, &startup(false)), 0);
    assert_eq!(exec(&mut tpm, &extend(16)), 0);
    assert_eq!(exec(&mut tpm, &shutdown(true)), 0);
    // Hashing and AES were tested before Startup and the extend; P-256 is next, before the
    // first command that may use a key.
    fail.set(true);
    assert_eq!(exec(&mut tpm, &extend(16)), 0);
    assert_eq!(tpm.execute(Locality::ZERO, &plain_session()), FAILURE);

    // Anything but the two is TPM_RC_FAILURE, before its frame is even checked.
    for c in [extend(16), startup(false), self_test(true), vec![0x80], vec![]] {
        assert_eq!(tpm.execute(Locality::ZERO, &c), FAILURE, "{c:02x?}");
    }
    assert_eq!(tpm.execute(Locality::ZERO, &get_test_result()), failed_at(3));
    let property = |tpm: &mut Janus<Faulty>, pt: u32, count: u32| {
        tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x17A, &get_capability(6, pt, count)))
    };
    // One vendor property at a time, below MANUFACTURER clamped to it.
    let jnus = [0x80, 0x01, 0, 0, 0, 27, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 1];
    for (pt, count) in [(0x105, 1), (0x100, 8), (0, 1)] {
        let mut want = jnus.to_vec();
        want.extend_from_slice(&[0, 0, 1, 0x05, b'J', b'N', b'U', b'S']);
        assert_eq!(property(&mut tpm, pt, count), want, "{pt:#x}");
    }
    let mut last = vec![0x80, 0x01, 0, 0, 0, 27, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 1];
    last.extend_from_slice(&[0, 0, 1, 0x0C, 0, 0, 0, 0]);
    assert_eq!(property(&mut tpm, 0x10C, 1), last);
    // No properties asked for, or none past FIRMWARE_VERSION_2: an empty list.
    let empty = |more: u8| vec![0x80, 0x01, 0, 0, 0, 19, 0, 0, 0, 0, more, 0, 0, 0, 6, 0, 0, 0, 0];
    assert_eq!(property(&mut tpm, 0x105, 0), empty(1));
    assert_eq!(property(&mut tpm, 0x200, 1), empty(0));
    // Not exactly what the reference parses: TPM_RC_FAILURE.
    let mut long = cmd(NO_SESSIONS, 0x17A, &get_capability(6, 0x105, 1));
    long.extend_from_slice(&[0; 4]);
    long[5] = 26;
    for c in [
        cmd(NO_SESSIONS, 0x17A, &get_capability(0, 0x105, 1)),
        cmd(SESSIONS, 0x17A, &get_capability(6, 0x105, 1)),
        cmd(NO_SESSIONS, 0x17A, &get_capability(6, 0x105, 1)[..8]),
        long,
        cmd(NO_SESSIONS, 0x17C, &[0]),
        cmd(SESSIONS, 0x17C, &[]),
    ] {
        assert_eq!(tpm.execute(Locality::ZERO, &c), FAILURE, "{c:02x?}");
    }

    // A _TPM_Init leaves failure mode with nothing changed: the Shutdown(STATE) before it is
    // resumed.
    tpm.init();
    fail.set(false);
    assert_eq!(exec(&mut tpm, &startup(true)), 0);
    assert_eq!(exec(&mut tpm, &plain_session()), 0);

    // A failure while the TPM waits for Startup: Startup itself hashes.
    tpm.init();
    fail.set(true);
    assert_eq!(tpm.execute(Locality::ZERO, &startup(false)), FAILURE);
    assert_eq!(tpm.execute(Locality::ZERO, &get_test_result()), failed_at(1));
    tpm.init();
    fail.set(false);
    assert_eq!(exec(&mut tpm, &startup(false)), 0);
}

#[test]
fn self_test_tests_what_is_left_or_everything_again() {
    let fail = std::rc::Rc::new(std::cell::Cell::new(false));
    let mut tpm = Janus::manufacture(Faulty(fail.clone()));
    tpm.init();
    assert_eq!(exec(&mut tpm, &startup(false)), 0);
    assert_eq!(exec(&mut tpm, &self_test(false)), 0);
    // Everything is tested: a partial test has nothing left to fail.
    fail.set(true);
    assert_eq!(exec(&mut tpm, &self_test(false)), 0);
    assert_eq!(exec(&mut tpm, &plain_session()), 0);
    // A full test starts over, with hashing.
    assert_eq!(tpm.execute(Locality::ZERO, &self_test(true)), FAILURE);
    assert_eq!(tpm.execute(Locality::ZERO, &get_test_result()), failed_at(1));
}
