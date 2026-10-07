// SPDX-License-Identifier: MIT OR Apache-2.0

//! HMAC sessions end to end, against a client written here from the specification.
//!
//! The guest corpus cannot replay these: a guest's session is salted to swtpm's key, whose
//! private part only swtpm has. So this file is the guest instead. It does what the Linux
//! kernel does at boot (a null-hierarchy primary key, a session salted to it, encrypted
//! GetRandom, an HMAC-authorized PCR_Extend) and what tpm2-tss does for a bound session that
//! encrypts a new authorization value, computing every key, HMAC and keystream itself with the
//! RustCrypto primitives and none of janus's code. Each response's HMAC is checked, so a janus
//! that answered with the wrong key or the wrong nonces fails here, not in a guest.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use aes::cipher::KeyIvInit;
use hmac::{KeyInit, Mac};
use janus::{Janus, Locality, Platform};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest as _, Sha256};

#[path = "support/watchdog.rs"]
mod watchdog;

/// Deterministic randomness that remembers what it gave, so a test can check what GetRandom
/// encrypted. Once `stuck`, it gives only zeros, as a failed entropy source might.
#[derive(Clone)]
struct Recorder {
    next: Rc<RefCell<u8>>,
    given: Rc<RefCell<Vec<Vec<u8>>>>,
    stuck: Rc<Cell<bool>>,
}

impl Platform for Recorder {
    fn fill_random(&mut self, buf: &mut [u8]) {
        if self.stuck.get() {
            buf.fill(0);
            self.given.borrow_mut().push(buf.to_vec());
            return;
        }
        for b in buf.iter_mut() {
            let mut n = self.next.borrow_mut();
            *n = n.wrapping_add(1);
            *b = *n;
        }
        self.given.borrow_mut().push(buf.to_vec());
    }

    fn now_ms(&mut self) -> u64 {
        0
    }
}

const SHA256: u16 = 0x000B;
const RH_NULL: u32 = 0x4000_0007;
const RH_OWNER: u32 = 0x4000_0001;
const RS_PW: u32 = 0x4000_0009;
const CONTINUE: u8 = 0x01;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;

/// The kernel's null primary template (`tpm2-sessions.c`): ECC P-256, restricted decrypt,
/// AES-128-CFB for children, noDA.
const KERNEL_TEMPLATE: &str = "0023000b00030472000000060080004300100003001000000000";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

fn tpm2b(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().to_vec()
}

/// Part 1 §11.4.10.2, for whole bytes.
fn kdfa(key: &[u8], label: &str, u: &[u8], v: &[u8], bits: u32) -> Vec<u8> {
    let mut label = label.as_bytes().to_vec();
    label.push(0);
    let mut out = Vec::new();
    let mut i: u32 = 0;
    while out.len() * 8 < bits as usize {
        i += 1;
        out.extend(hmac(key, &[&i.to_be_bytes(), &label, u, v, &bits.to_be_bytes()]));
    }
    out.truncate(bits as usize / 8);
    out
}

/// Part 1 §11.4.10.3, for whole bytes.
fn kdfe(z: &[u8], label: &str, u: &[u8], v: &[u8], bits: u32) -> Vec<u8> {
    let mut label = label.as_bytes().to_vec();
    label.push(0);
    let mut out = Vec::new();
    let mut i: u32 = 0;
    while out.len() * 8 < bits as usize {
        i += 1;
        out.extend(sha256(&[&i.to_be_bytes(), z, &label, u, v]));
    }
    out.truncate(bits as usize / 8);
    out
}

fn cfb(key_iv: &[u8], data: &mut [u8], encrypt: bool) {
    let key: [u8; 16] = key_iv[..16].try_into().unwrap();
    let iv: [u8; 16] = key_iv[16..32].try_into().unwrap();
    let (key, iv) = (&key, &iv);
    if encrypt {
        cfb_mode::Encryptor::<aes::Aes128>::new(key.into(), iv.into()).encrypt(data);
    } else {
        cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into()).decrypt(data);
    }
}

fn command(tag: u16, cc: u32, handles: &[u32], area: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&cc.to_be_bytes());
    for h in handles {
        v.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(a) = area {
        v.extend_from_slice(&(a.len() as u32).to_be_bytes());
        v.extend_from_slice(a);
    }
    v.extend_from_slice(params);
    let len = v.len() as u32;
    v[2..6].copy_from_slice(&len.to_be_bytes());
    v
}

fn rc(rsp: &[u8]) -> u32 {
    u32_at(rsp, 6)
}

/// A TPM with a recorder for randomness, started.
fn started() -> (Janus<Recorder>, Recorder) {
    let platform = Recorder { next: Rc::default(), given: Rc::default(), stuck: Rc::default() };
    let mut tpm = Janus::manufacture(platform.clone());
    tpm.init();
    let startup = command(0x8001, 0x144, &[], None, &[0, 0]);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup)), 0);
    (tpm, platform)
}

/// A session as the client sees it.
struct Session {
    handle: u32,
    key: Vec<u8>,
    nonce_caller: Vec<u8>,
    nonce_tpm: Vec<u8>,
}

impl Session {
    /// The session's entry in a command's authorization area. `auth` is the authorized
    /// entity's authValue when the HMAC must include it, `extra` the decrypt and encrypt
    /// sessions' nonces when they are other sessions.
    fn entry(&self, cp_hash: &[u8], attrs: u8, auth: &[u8]) -> Vec<u8> {
        let key = [&self.key[..], auth].concat();
        let mac = hmac(&key, &[cp_hash, &self.nonce_caller, &self.nonce_tpm, &[attrs]]);
        let mut v = self.handle.to_be_bytes().to_vec();
        v.extend(tpm2b(&self.nonce_caller));
        v.push(attrs);
        v.extend(tpm2b(&mac));
        v
    }

    /// Checks the session's entry in a response and takes its new nonce; returns the bytes
    /// after it.
    fn check<'a>(&mut self, rp_hash: &[u8], attrs: u8, auth: &[u8], area: &'a [u8]) -> &'a [u8] {
        let n = u16_at(area, 0) as usize;
        let nonce_tpm = area[2..2 + n].to_vec();
        assert_ne!(nonce_tpm, self.nonce_tpm, "the TPM did not roll its nonce");
        assert_eq!(area[2 + n], attrs, "the response's session attributes");
        let m = u16_at(area, 3 + n) as usize;
        let mac = &area[5 + n..5 + n + m];
        let key = [&self.key[..], auth].concat();
        assert_eq!(
            mac,
            hmac(&key, &[rp_hash, &nonce_tpm, &self.nonce_caller, &[attrs]]),
            "the response HMAC does not verify"
        );
        self.nonce_tpm = nonce_tpm;
        // The caller's next nonce: a fresh one each command, as a TSS would.
        for b in &mut self.nonce_caller {
            *b = b.wrapping_add(0x11);
        }
        &area[5 + n + m..]
    }

    /// The CFB key and IV for parameter encryption.
    fn cipher(&self, auth: &[u8], command: bool) -> Vec<u8> {
        let key = [&self.key[..], auth].concat();
        if command {
            kdfa(&key, "CFB", &self.nonce_caller, &self.nonce_tpm, 256)
        } else {
            kdfa(&key, "CFB", &self.nonce_tpm, &self.nonce_caller, 256)
        }
    }
}

/// `TPM2_CreatePrimary` in the null hierarchy with the kernel's template; returns the handle
/// and the public point.
fn kernel_primary(tpm: &mut Janus<Recorder>) -> (u32, Vec<u8>, Vec<u8>) {
    let pw = [RS_PW.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 0]].concat();
    let template = hex(KERNEL_TEMPLATE);
    let params = [&[0, 4, 0, 0, 0, 0][..], &tpm2b(&template), &[0, 0], &[0, 0, 0, 0]].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x131, &[RH_NULL], Some(&pw), &params));
    assert_eq!(rc(&rsp), 0, "CreatePrimary");
    let handle = u32_at(&rsp, 10);
    // header (10), handle (4), parameterSize (4), outPublic: size (2), then the area, which
    // ends with x and y as TPM2Bs.
    let size = u16_at(&rsp, 18) as usize;
    let public = &rsp[20..20 + size];
    let x = public[public.len() - 66..public.len() - 34].to_vec();
    let y = public[public.len() - 32..].to_vec();
    (handle, x, y)
}

/// Starts a session salted to the ECC key `(handle, x, y)` and bound to `bind` whose authValue
/// is `bind_auth`, as the kernel and tpm2-tss do.
fn start_salted(
    tpm: &mut Janus<Recorder>,
    key: (u32, &[u8], &[u8]),
    bind: u32,
    bind_auth: &[u8],
) -> Session {
    let ephemeral = p256::SecretKey::from_slice(&[0x5A; 32]).unwrap();
    let q = ephemeral.public_key().to_sec1_point(false);
    let (qx, qy) = (q.x().unwrap().to_vec(), q.y().unwrap().to_vec());
    let tpm_key = p256::PublicKey::from_sec1_bytes(&[&[4u8][..], key.1, key.2].concat()).unwrap();
    let z = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), tpm_key.as_affine());
    let salt = kdfe(z.raw_secret_bytes().as_slice(), "SECRET", &qx, key.1, 256);
    let nonce_caller = vec![0xC3; 32];
    let point = [tpm2b(&qx), tpm2b(&qy)].concat();
    let params = [
        tpm2b(&nonce_caller),
        tpm2b(&point),
        vec![0x00],                               // TPM_SE_HMAC
        vec![0x00, 0x06, 0x00, 0x80, 0x00, 0x43], // AES-128-CFB
        SHA256.to_be_bytes().to_vec(),
    ]
    .concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x176, &[key.0, bind], None, &params));
    assert_eq!(rc(&rsp), 0, "StartAuthSession");
    let handle = u32_at(&rsp, 10);
    let n = u16_at(&rsp, 14) as usize;
    let nonce_tpm = rsp[16..16 + n].to_vec();
    let session_key = kdfa(&[bind_auth, &salt].concat(), "ATH", &nonce_tpm, &nonce_caller, 256);
    Session { handle, key: session_key, nonce_caller, nonce_tpm }
}

#[test]
fn the_kernels_boot_sequence_works_against_its_own_key() {
    let (mut tpm, platform) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);

    // GetRandom(32), the response encrypted.
    let params = 32u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0, "GetRandom");
    let size = u32_at(&rsp, 10) as usize;
    let out = &rsp[14..14 + size];
    let rp = sha256(&[&0u32.to_be_bytes(), &0x17Bu32.to_be_bytes(), out]);
    let given = platform.given.borrow();
    let expected = given[given.len() - 2].clone();
    drop(given);
    let rest = s.check(&rp, CONTINUE | ENCRYPT, &[], &rsp[14 + size..]);
    assert!(rest.is_empty());
    let mut bytes = out[2..].to_vec();
    // The keystream is derived from the nonces as they were when the TPM encrypted: its new
    // one, and the caller's from the command.
    let mut caller = s.nonce_caller.clone();
    for b in &mut caller {
        *b = b.wrapping_sub(0x11);
    }
    let keystream = kdfa(&s.key, "CFB", &s.nonce_tpm, &caller, 256);
    cfb(&keystream, &mut bytes, false);
    assert_eq!(bytes, expected, "GetRandom's bytes did not decrypt to what the TPM drew");

    // PCR_Extend(10) authorized by the session, which is not bound: the PCR's empty authValue
    // joins the key.
    let digest = [0xEE; 32];
    let params = [&1u32.to_be_bytes()[..], &SHA256.to_be_bytes(), &digest].concat();
    let name = 10u32.to_be_bytes();
    let cp = sha256(&[&0x182u32.to_be_bytes(), &name, &params]);
    let area = s.entry(&cp, CONTINUE, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x182, &[10], Some(&area), &params));
    assert_eq!(rc(&rsp), 0, "PCR_Extend");
    let rp = sha256(&[&0u32.to_be_bytes(), &0x182u32.to_be_bytes()]);
    assert_eq!(u32_at(&rsp, 10), 0);
    s.check(&rp, CONTINUE, &[], &rsp[14..]);

    // PCR 10 holds the extend.
    let read = command(0x8001, 0x17E, &[], None, &[0, 0, 0, 1, 0, 0x0B, 3, 0, 4, 0]);
    let rsp = tpm.execute(Locality::ZERO, &read);
    assert_eq!(rc(&rsp), 0);
    assert_eq!(&rsp[rsp.len() - 32..], sha256(&[&[0; 32], &digest]).as_slice());
}

#[test]
fn a_wrong_hmac_is_bad_auth_and_leaves_the_session_usable() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let mut area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let last = area.len() - 1;
    area[last] ^= 1;
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    // TPM_RC_BAD_AUTH on session 1: the session is not bound to anything subject to DA.
    assert_eq!(rc(&rsp), 0x9A2);
    // Nothing rolled: the same nonces still work.
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
}

#[test]
fn a_session_that_does_not_continue_is_flushed() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let area = s.entry(&cp, ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
    let size = u32_at(&rsp, 10) as usize;
    let rp = sha256(&[&0u32.to_be_bytes(), &0x17Bu32.to_be_bytes(), &rsp[14..14 + size]]);
    s.check(&rp, ENCRYPT, &[], &rsp[14 + size..]);
    let area = s.entry(&cp, ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    // TPM_RC_REFERENCE_S0.
    assert_eq!(rc(&rsp), 0x918);
}

#[test]
fn a_saved_session_loads_back_once_and_keeps_working() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    let save = command(0x8001, 0x162, &[s.handle], None, &[]);
    let rsp = tpm.execute(Locality::ZERO, &save);
    assert_eq!(rc(&rsp), 0);
    let context = rsp[10..].to_vec();
    // Saved, it cannot be used.
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0x918);
    let load = command(0x8001, 0x161, &[], None, &context);
    let rsp = tpm.execute(Locality::ZERO, &load);
    assert_eq!(rc(&rsp), 0);
    assert_eq!(u32_at(&rsp, 10), s.handle);
    // A second load of the same context: TPM_RC_HANDLE on parameter 1.
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &load)), 0x1CB);
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
    let size = u32_at(&rsp, 10) as usize;
    let rp = sha256(&[&0u32.to_be_bytes(), &0x17Bu32.to_be_bytes(), &rsp[14..14 + size]]);
    s.check(&rp, CONTINUE | ENCRYPT, &[], &rsp[14 + size..]);
}

#[test]
fn a_bound_session_changes_an_authorization_it_sends_encrypted() {
    let (mut tpm, _) = started();
    // The owner gets a password first, over a password session.
    let pw_area = [RS_PW.to_be_bytes().to_vec(), vec![0, 0, CONTINUE, 0, 0]].concat();
    let change = command(0x8002, 0x129, &[RH_OWNER], Some(&pw_area), &tpm2b(b"first"));
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &change)), 0);

    // An unsalted session bound to the owner: its key comes from the owner's authValue alone.
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_OWNER, b"first");

    // HierarchyChangeAuth(owner, "second"), newAuth encrypted. The session is bound to the
    // owner, so the HMAC key leaves the authValue out; the encryption key always includes it.
    let mut new = b"second".to_vec();
    cfb(&s.cipher(b"first", true), &mut new, true);
    let params = tpm2b(&new);
    let name = RH_OWNER.to_be_bytes();
    let cp = sha256(&[&0x129u32.to_be_bytes(), &name, &params]);
    let area = s.entry(&cp, CONTINUE | DECRYPT, &[]);
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x129, &[RH_OWNER], Some(&area), &params));
    assert_eq!(rc(&rsp), 0, "HierarchyChangeAuth");
    let rp = sha256(&[&0u32.to_be_bytes(), &0x129u32.to_be_bytes()]);
    s.check(&rp, CONTINUE | DECRYPT, &[], &rsp[14..]);

    // The new value is what the session decrypted.
    let pw = |p: &[u8]| [RS_PW.to_be_bytes().to_vec(), vec![0, 0, CONTINUE], tpm2b(p)].concat();
    let again = command(0x8002, 0x129, &[RH_OWNER], Some(&pw(b"second")), &tpm2b(b"third"));
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &again)), 0);
    let stale = command(0x8002, 0x129, &[RH_OWNER], Some(&pw(b"second")), &tpm2b(b"x"));
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &stale)), 0x9A2);
}

#[test]
fn an_unbound_session_answers_a_change_under_the_new_authorization() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    // Owner's authValue is empty, so the command HMAC key is the session key alone; the
    // response's is the session key and the new value.
    let params = tpm2b(b"new");
    let name = RH_OWNER.to_be_bytes();
    let cp = sha256(&[&0x129u32.to_be_bytes(), &name, &params]);
    let area = s.entry(&cp, CONTINUE, &[]);
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x129, &[RH_OWNER], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
    let rp = sha256(&[&0u32.to_be_bytes(), &0x129u32.to_be_bytes()]);
    s.check(&rp, CONTINUE, b"new", &rsp[14..]);
}

#[test]
fn an_empty_parameter_under_a_decrypt_session_is_accepted() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let mut s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    // HierarchyChangeAuth(owner, empty): there is nothing to decrypt, and nothing after it.
    let params = tpm2b(&[]);
    let cp = sha256(&[&0x129u32.to_be_bytes(), &RH_OWNER.to_be_bytes(), &params]);
    let area = s.entry(&cp, CONTINUE | DECRYPT, &[]);
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x129, &[RH_OWNER], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
    let rp = sha256(&[&0u32.to_be_bytes(), &0x129u32.to_be_bytes()]);
    s.check(&rp, CONTINUE | DECRYPT, &[], &rsp[14..]);
}

#[test]
fn a_session_that_authorizes_nothing_must_encrypt_or_decrypt() {
    let (mut tpm, _) = started();
    let (key, x, y) = kernel_primary(&mut tpm);
    let s = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    // GetRandom authorizes nothing, so a session there is for parameter encryption or audit:
    // TPM_RC_ATTRIBUTES on session 1 (SessionProcess.c, ParseSessionBuffer).
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let area = s.entry(&cp, CONTINUE, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0x982);
}

/// `TPM_PT_LOCKOUT_COUNTER`.
fn lockout_counter(tpm: &mut Janus<Recorder>) -> u32 {
    let params = [6u32.to_be_bytes(), 0x20Eu32.to_be_bytes(), 1u32.to_be_bytes()].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x17A, &[], None, &params));
    assert_eq!(rc(&rsp), 0);
    assert_eq!(u32_at(&rsp, 19), 0x20E);
    u32_at(&rsp, 23)
}

/// A session bound to an entity subject to dictionary-attack protection carries it: its
/// failed HMAC counts a failure even where it authorizes nothing (`IncrementLockout`), and it is
/// refused while that protection is locked out (`ExecCommand`'s session loop).
#[test]
fn a_session_bound_to_a_protected_key_counts_its_failures_and_locks_out() {
    let (mut tpm, _) = started();
    // An unrestricted ECC key without noDA, under an empty authValue.
    let (protected, _) = primary(&mut tpm, RH_OWNER, ECC_KEY_TEMPLATE);
    let (key, x, y) = kernel_primary(&mut tpm);
    let s = start_salted(&mut tpm, (key, &x, &y), protected, &[]);
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    for n in 1..=3 {
        let mut area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
        let last = area.len() - 1;
        area[last] ^= 1;
        let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
        // TPM_RC_AUTH_FAIL on session 1, counted.
        assert_eq!(rc(&rsp), 0x98E, "failure {n}");
        assert_eq!(lockout_counter(&mut tpm), n);
    }
    // At maxTries the session is refused before its HMAC is looked at.
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0x921);
    // An unbound session is not.
    let free = start_salted(&mut tpm, (key, &x, &y), RH_NULL, &[]);
    let area = free.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0);
}

const TPM_SE_POLICY: u8 = 0x01;
const TPM_SE_TRIAL: u8 = 0x03;
const NO_SYMMETRIC: [u8; 2] = [0x00, 0x10];
const AES_128_CFB: [u8; 6] = [0x00, 0x06, 0x00, 0x80, 0x00, 0x43];

/// A storage key in the owner hierarchy: the kernel's template, which allows its authValue.
fn owner_primary(tpm: &mut Janus<Recorder>) -> u32 {
    let pw = [RS_PW.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 0]].concat();
    let template = hex(KERNEL_TEMPLATE);
    let params = [&[0, 4, 0, 0, 0, 0][..], &tpm2b(&template), &[0, 0], &[0, 0, 0, 0]].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x131, &[RH_OWNER], Some(&pw), &params));
    assert_eq!(rc(&rsp), 0, "CreatePrimary");
    u32_at(&rsp, 10)
}

/// An unsalted, unbound policy or trial session: its session key is empty.
fn start_policy(tpm: &mut Janus<Recorder>, kind: u8, symmetric: &[u8]) -> Session {
    let nonce_caller = vec![0x7E; 32];
    let params = [
        tpm2b(&nonce_caller),
        tpm2b(&[]),
        vec![kind],
        symmetric.to_vec(),
        SHA256.to_be_bytes().to_vec(),
    ]
    .concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8001, 0x176, &[RH_NULL, RH_NULL], None, &params));
    assert_eq!(rc(&rsp), 0, "StartAuthSession");
    let n = u16_at(&rsp, 14) as usize;
    Session {
        handle: u32_at(&rsp, 10),
        key: Vec::new(),
        nonce_caller,
        nonce_tpm: rsp[16..16 + n].to_vec(),
    }
}

/// `TPML_PCR_SELECTION` for SHA-256 PCR 7.
const PCR7: [u8; 10] = [0, 0, 0, 1, 0, 0x0B, 3, 0x80, 0, 0];

/// TPM2_PolicyPCR(PCR 7) then TPM2_PolicyAuthValue on `session`; returns the digest it holds.
fn pcr7_and_auth_value(tpm: &mut Janus<Recorder>, session: u32) -> Vec<u8> {
    let params = [&tpm2b(&[])[..], &PCR7].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x17F, &[session], None, &params));
    assert_eq!(rc(&rsp), 0, "PolicyPCR");
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x16B, &[session], None, &[]));
    assert_eq!(rc(&rsp), 0, "PolicyAuthValue");
    policy_digest(tpm, session)
}

fn policy_digest(tpm: &mut Janus<Recorder>, session: u32) -> Vec<u8> {
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x189, &[session], None, &[]));
    assert_eq!(rc(&rsp), 0, "PolicyGetDigest");
    rsp[12..].to_vec()
}

/// The policy `PolicyPCR(PCR 7 = pcr7) || PolicyAuthValue`, from Part 3 §23.7 and §23.18.
fn expected_policy(pcr7: &[u8]) -> Vec<u8> {
    let after_pcr = sha256(&[&[0; 32], &0x17Fu32.to_be_bytes(), &PCR7, &sha256(&[pcr7])]);
    sha256(&[&after_pcr, &0x16Bu32.to_be_bytes()])
}

fn pw_area() -> Vec<u8> {
    [RS_PW.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 0]].concat()
}

/// `TPMA_OBJECT` fixedTPM | fixedParent | noDA: a sealed object only its policy authorizes.
const SEALED: u32 = 0x0000_0412;
/// `TPMA_OBJECT` userWithAuth: its authValue authorizes it too.
const USER_WITH_AUTH: u32 = 0x0000_0040;

/// `TPMA_OBJECT` sign.
const SIGN: u32 = 0x0004_0000;

/// Seals `data` under `parent` with authValue `auth` and policy `policy`, and loads it;
/// returns the sealed object's handle and name, and its private and public areas.
fn seal(
    tpm: &mut Janus<Recorder>,
    parent: u32,
    auth: &[u8],
    policy: &[u8],
    data: &[u8],
    attributes: u32,
) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>) {
    // KEYEDHASH, SHA-256, empty unique.
    let template = [
        &[0x00, 0x08, 0x00, 0x0B][..],
        &attributes.to_be_bytes(),
        &tpm2b(policy),
        // An HMAC key names its scheme, HMAC-SHA-256; sealed data has none.
        if attributes & SIGN != 0 { &[0x00, 0x05, 0x00, 0x0B][..] } else { &[0x00, 0x10] },
        &[0, 0],
    ]
    .concat();
    let sensitive = [tpm2b(auth), tpm2b(data)].concat();
    let params = [tpm2b(&sensitive), tpm2b(&template), vec![0, 0], vec![0, 0, 0, 0]].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x153, &[parent], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0, "Create");
    let n = u16_at(&rsp, 14) as usize;
    let private = rsp[16..16 + n].to_vec();
    let m = u16_at(&rsp, 16 + n) as usize;
    let public = rsp[18 + n..18 + n + m].to_vec();
    // The template, but for its unique field, which the TPM fills with H(seedValue || data).
    assert_eq!(public[..template.len() - 2], template[..template.len() - 2]);
    assert_eq!(public[template.len() - 2..template.len()], [0, 32], "the unique digest's size");
    let params = [tpm2b(&private), tpm2b(&public)].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x157, &[parent], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0, "Load");
    let handle = u32_at(&rsp, 10);
    let name = rsp[20..20 + u16_at(&rsp, 18) as usize].to_vec();
    assert_eq!(
        name,
        [&SHA256.to_be_bytes()[..], &sha256(&[&public])].concat(),
        "the object's name"
    );
    (handle, name, private, public)
}

/// TPM2_Unseal of `item` (named `name`, authValue `auth`) under the policy session `s`, its
/// response encrypted; returns the response code and, on success, the decrypted data.
fn unseal(
    tpm: &mut Janus<Recorder>,
    s: &mut Session,
    item: u32,
    name: &[u8],
    auth: &[u8],
) -> (u32, Vec<u8>) {
    let cp = sha256(&[&0x15Eu32.to_be_bytes(), name]);
    let area = s.entry(&cp, CONTINUE | ENCRYPT, auth);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x15E, &[item], Some(&area), &[]));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new());
    }
    let size = u32_at(&rsp, 10) as usize;
    let out = &rsp[14..14 + size];
    let rp = sha256(&[&0u32.to_be_bytes(), &0x15Eu32.to_be_bytes(), out]);
    let caller = s.nonce_caller.clone();
    let rest = s.check(&rp, CONTINUE | ENCRYPT, auth, &rsp[14 + size..]);
    assert!(rest.is_empty());
    let keystream = kdfa(&[&s.key[..], auth].concat(), "CFB", &s.nonce_tpm, &caller, 256);
    let mut bytes = out[2..].to_vec();
    cfb(&keystream, &mut bytes, false);
    (0, bytes)
}

#[test]
fn a_secret_sealed_to_pcr7_and_a_password_unseals_until_pcr7_moves() {
    let (mut tpm, _) = started();
    let srk = owner_primary(&mut tpm);

    // A trial session computes the policy without checking it.
    let trial = start_policy(&mut tpm, TPM_SE_TRIAL, &NO_SYMMETRIC);
    let policy = pcr7_and_auth_value(&mut tpm, trial.handle);
    assert_eq!(policy, expected_policy(&[0; 32]), "the trial policy digest");

    let (item, name, _, _) = seal(&mut tpm, srk, b"pin", &policy, b"disk key", SEALED);

    let mut s = start_policy(&mut tpm, TPM_SE_POLICY, &AES_128_CFB);
    assert_eq!(pcr7_and_auth_value(&mut tpm, s.handle), policy);
    assert_eq!(unseal(&mut tpm, &mut s, item, &name, b"pin"), (0, b"disk key".to_vec()));
    // A policy session that authorized a command starts over.
    assert_eq!(policy_digest(&mut tpm, s.handle), vec![0; 32]);

    // The wrong authValue is BAD_AUTH on the session; noDA keeps it from counting.
    pcr7_and_auth_value(&mut tpm, s.handle);
    assert_eq!(unseal(&mut tpm, &mut s, item, &name, b"pun").0, 0x9A2);

    // PCR 7 moves after the policy was satisfied: TPM_RC_PCR_CHANGED.
    let extend = [&1u32.to_be_bytes()[..], &SHA256.to_be_bytes(), &[0xAB; 32]].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x182, &[7], Some(&pw_area()), &extend));
    assert_eq!(rc(&rsp), 0, "PCR_Extend");
    assert_eq!(unseal(&mut tpm, &mut s, item, &name, b"pin").0, 0x128);

    // Satisfied afresh against the new PCR 7, the policy is a different policy:
    // TPM_RC_POLICY_FAIL on session 1.
    let restart = tpm.execute(Locality::ZERO, &command(0x8001, 0x180, &[s.handle], None, &[]));
    assert_eq!(rc(&restart), 0, "PolicyRestart");
    assert_eq!(policy_digest(&mut tpm, s.handle), vec![0; 32]);
    let now = pcr7_and_auth_value(&mut tpm, s.handle);
    assert_eq!(now, expected_policy(&sha256(&[&[0; 32], &[0xAB; 32]])));
    assert_eq!(unseal(&mut tpm, &mut s, item, &name, b"pin").0, 0x99D);
}

#[test]
fn load_refuses_private_areas_in_the_reference_order() {
    let (mut tpm, _) = started();
    let srk = owner_primary(&mut tpm);
    let (item, _, private, public) =
        seal(&mut tpm, srk, b"", &[0x11; 32], b"x", SEALED | USER_WITH_AUTH);
    let load = |tpm: &mut Janus<Recorder>, parent: u32, private: &[u8]| {
        let params = [tpm2b(private), tpm2b(&public)].concat();
        rc(&tpm
            .execute(Locality::ZERO, &command(0x8002, 0x157, &[parent], Some(&pw_area()), &params)))
    };
    // TPM_RC_SIZE on the private area for an empty one.
    assert_eq!(load(&mut tpm, srk, &[]), 0x1D5);
    // TPM_RC_INTEGRITY on it for any flipped byte, the integrity, the IV or the ciphertext.
    for i in [2, 2 + 32 + 2, private.len() - 1] {
        let mut bad = private.clone();
        bad[i] ^= 1;
        assert_eq!(load(&mut tpm, srk, &bad), 0x1DF, "flipped byte {i}");
    }
    // With another public area, which is another name, the integrity fails: the name is
    // bound into it.
    let mut other = public.clone();
    other[10] ^= 1;
    let params = [tpm2b(&private), tpm2b(&other)].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x157, &[srk], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0x1DF, "another object's public area");
    // Under an object that is not a parent: TPM_RC_TYPE on the parent handle.
    assert_eq!(load(&mut tpm, item, &private), 0x18A);
    // Unsealing a key that is not a sealed object: TPM_RC_TYPE on its handle.
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x15E, &[srk], Some(&pw_area()), &[]));
    assert_eq!(rc(&rsp), 0x18A);
    // An HMAC key is a keyed-hash object too, but not data to hand out: TPM_RC_ATTRIBUTES on
    // its handle. (Flushed after, to keep the slot count below.)
    let (key, ..) = seal(&mut tpm, srk, b"", &[0x11; 32], b"k", SEALED | USER_WITH_AUTH | SIGN);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x15E, &[key], Some(&pw_area()), &[]));
    assert_eq!(rc(&rsp), 0x182);
    let flush = command(0x8001, 0x165, &[], None, &key.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &flush)), 0);
    // One slot is left after the key and the sealed object; filling it leaves none.
    assert_eq!(load(&mut tpm, srk, &private), 0);
    assert_eq!(load(&mut tpm, srk, &private), 0x902, "TPM_RC_OBJECT_MEMORY");
}

/// tpm2-pkcs11's storage primary (`tests/corpus/06-pkcs11`): RSA-2048, restricted decrypt,
/// AES-128-CFB for its children.
const RSA_SRK_TEMPLATE: &str = "0001000b00030072000000060080004300100800000000000000";
/// ssh-tpm-agent's keys (`tests/corpus/05-ssh-tpm-agent`): unrestricted, sign and decrypt, no
/// scheme of their own.
const RSA_KEY_TEMPLATE: &str = "0001000b000600720000001000100800000000000000";
const ECC_KEY_TEMPLATE: &str = "0023000b000600720000001000100003001000000000";
/// A restricted ECDSA-SHA256 signing key, as an attestation key is.
const RESTRICTED_ECC_TEMPLATE: &str = "0023000b00050072000000100018000b0003001000000000";

fn primary(tpm: &mut Janus<Recorder>, hierarchy: u32, template: &str) -> (u32, Vec<u8>) {
    let params = [&[0, 4, 0, 0, 0, 0][..], &tpm2b(&hex(template)), &[0, 0], &[0, 0, 0, 0]].concat();
    let rsp = tpm
        .execute(Locality::ZERO, &command(0x8002, 0x131, &[hierarchy], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0, "CreatePrimary");
    let n = u16_at(&rsp, 18) as usize;
    (u32_at(&rsp, 10), rsp[20..20 + n].to_vec())
}

/// Creates and loads a key with an empty authValue under `parent`; returns its handle and
/// public area.
fn child(tpm: &mut Janus<Recorder>, parent: u32, template: &str) -> (u32, Vec<u8>) {
    let params =
        [tpm2b(&[0, 0, 0, 0]), tpm2b(&hex(template)), vec![0, 0], vec![0, 0, 0, 0]].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x153, &[parent], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0, "Create");
    let n = u16_at(&rsp, 14) as usize;
    let private = rsp[16..16 + n].to_vec();
    let m = u16_at(&rsp, 16 + n) as usize;
    let public = rsp[18 + n..18 + n + m].to_vec();
    let params = [tpm2b(&private), tpm2b(&public)].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x157, &[parent], Some(&pw_area()), &params));
    assert_eq!(rc(&rsp), 0, "Load");
    (u32_at(&rsp, 10), public)
}

/// An RSA public area's modulus, its last field.
fn modulus(public: &[u8]) -> Vec<u8> {
    let m = &public[public.len() - 256..];
    assert_eq!(u16_at(public, public.len() - 258), 256);
    m.to_vec()
}

fn rsa_public(public: &[u8]) -> rsa::RsaPublicKey {
    let n = rsa::BoxedUint::from_be_slice(&modulus(public), 2048).unwrap();
    rsa::RsaPublicKey::new(n, rsa::BoxedUint::from(65537u64)).unwrap()
}

/// A NULL `TPMT_TK_HASHCHECK`.
const NULL_TICKET: [u8; 8] = [0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00];

/// TPM2_Sign with `key`; returns the response code and the TPMT_SIGNATURE.
fn sign(
    tpm: &mut Janus<Recorder>,
    key: u32,
    digest: &[u8],
    scheme: &[u8],
    ticket: &[u8],
) -> (u32, Vec<u8>) {
    let params = [&tpm2b(digest)[..], scheme, ticket].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x15D, &[key], Some(&pw_area()), &params));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new());
    }
    let size = u32_at(&rsp, 10) as usize;
    (0, rsp[14..14 + size].to_vec())
}

fn rsa_decrypt(
    tpm: &mut Janus<Recorder>,
    key: u32,
    c: &[u8],
    scheme: &[u8],
    label: &[u8],
) -> (u32, Vec<u8>) {
    let params = [&tpm2b(c)[..], scheme, &tpm2b(label)].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x159, &[key], Some(&pw_area()), &params));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new());
    }
    (0, rsp[16..16 + u16_at(&rsp, 14) as usize].to_vec())
}

/// The RSA code draws until a value fits (a blinding factor below the modulus and invertible
/// mod it); fed straight from a platform that gives only zeros, it never finds one. janus
/// feeds it from a generator seeded per operation instead, so it ends.
#[test]
fn rsa_signs_and_decrypts_even_when_the_platform_gives_only_zeros() {
    let _deadline = watchdog::watchdog(120, "an RSA operation under a stuck platform");
    let (mut tpm, platform) = started();
    let (srk, _) = primary(&mut tpm, RH_OWNER, RSA_SRK_TEMPLATE);
    let (key, key_public) = child(&mut tpm, srk, RSA_KEY_TEMPLATE);
    platform.stuck.set(true);
    let verifier = rsa_public(&key_public);
    let digest = sha256(&[b"to be signed"]);
    let (code, sig) = sign(&mut tpm, key, &digest, &[0x00, 0x14, 0x00, 0x0B], &NULL_TICKET);
    assert_eq!(code, 0, "RSASSA");
    verifier
        .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, &sig[6..])
        .expect("RSASSA verifies");
    let (code, sig) = sign(&mut tpm, key, &digest, &[0x00, 0x16, 0x00, 0x0B], &NULL_TICKET);
    assert_eq!(code, 0, "RSAPSS");
    verifier.verify(rsa::Pss::<Sha256>::new(), &digest, &sig[6..]).expect("RSAPSS verifies");
    let c = verifier.encrypt(&mut Rng(0), rsa::Pkcs1v15Encrypt, b"a secret").unwrap();
    assert_eq!(rsa_decrypt(&mut tpm, key, &c, &[0x00, 0x15], b""), (0, b"a secret".to_vec()));
}

#[test]
fn an_rsa_storage_key_is_the_same_key_every_time_and_parents_keys() {
    let (mut tpm, _) = started();
    let (srk, public) = primary(&mut tpm, RH_OWNER, RSA_SRK_TEMPLATE);
    let n = modulus(&public);
    assert!(n[0] >= 0x80, "a 2048-bit modulus");
    // Derived again from the same seed and template: the same key.
    let flush = command(0x8001, 0x165, &[], None, &srk.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &flush)), 0);
    let (srk, again) = primary(&mut tpm, RH_OWNER, RSA_SRK_TEMPLATE);
    assert_eq!(again, public, "a primary key is a function of its seed and template");
    // In another hierarchy, another key.
    let (other, endorsement) = primary(&mut tpm, 0x4000_000B, RSA_SRK_TEMPLATE);
    assert_ne!(modulus(&endorsement), n);
    let flush = command(0x8001, 0x165, &[], None, &other.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &flush)), 0);

    // An RSA key under it signs, PKCS#1 v1.5 and PSS, and the signatures verify.
    let (key, key_public) = child(&mut tpm, srk, RSA_KEY_TEMPLATE);
    let verifier = rsa_public(&key_public);
    let digest = sha256(&[b"to be signed"]);
    let (code, sig) = sign(&mut tpm, key, &digest, &[0x00, 0x14, 0x00, 0x0B], &NULL_TICKET);
    assert_eq!(code, 0, "RSASSA");
    assert_eq!(sig[..6], [0x00, 0x14, 0x00, 0x0B, 0x01, 0x00]);
    verifier
        .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, &sig[6..])
        .expect("RSASSA verifies");
    let (code, sig) = sign(&mut tpm, key, &digest, &[0x00, 0x16, 0x00, 0x0B], &NULL_TICKET);
    assert_eq!(code, 0, "RSAPSS");
    verifier.verify(rsa::Pss::<Sha256>::new(), &digest, &sig[6..]).expect("RSAPSS verifies");
    // A key with no scheme of its own needs the caller's: TPM_RC_SCHEME on it.
    assert_eq!(sign(&mut tpm, key, &digest, &[0x00, 0x10], &NULL_TICKET).0, 0x2D2);
    // A digest of the wrong size: TPM_RC_SIZE on it.
    assert_eq!(
        sign(&mut tpm, key, &digest[..31], &[0x00, 0x14, 0x00, 0x0B], &NULL_TICKET).0,
        0x1D5
    );

    // It decrypts what was encrypted to it: OAEP with a label, and PKCS#1 v1.5.
    let mut rng = Rng(0);
    let secret = b"a symmetric key";
    let c = verifier
        .encrypt(&mut rng, rsa::Oaep::<Sha256>::new_with_label(&b"label\0"[..]), secret)
        .unwrap();
    assert_eq!(
        rsa_decrypt(&mut tpm, key, &c, &[0x00, 0x17, 0x00, 0x0B], b"label\0"),
        (0, secret.to_vec())
    );
    // Under another label, nothing: TPM_RC_VALUE.
    assert_eq!(rsa_decrypt(&mut tpm, key, &c, &[0x00, 0x17, 0x00, 0x0B], b"lapel\0").0, 0x084);
    // A label without its NUL: TPM_RC_VALUE on the label.
    assert_eq!(rsa_decrypt(&mut tpm, key, &c, &[0x00, 0x17, 0x00, 0x0B], b"label").0, 0x3C4);
    let c = verifier.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, secret).unwrap();
    assert_eq!(rsa_decrypt(&mut tpm, key, &c, &[0x00, 0x15], &[]), (0, secret.to_vec()));
    // A ciphertext the modulus' size but not below it: TPM_RC_SIZE.
    assert_eq!(rsa_decrypt(&mut tpm, key, &[0xFF; 256], &[0x00, 0x15], &[]).0, 0x095);
    // The storage key does not sign: TPM_RC_KEY on its handle.
    assert_eq!(sign(&mut tpm, srk, &digest, &[0x00, 0x14, 0x00, 0x0B], &NULL_TICKET).0, 0x19C);
    // The storage key is restricted: TPM_RC_ATTRIBUTES on its handle.
    assert_eq!(rsa_decrypt(&mut tpm, srk, &c, &[0x00, 0x15], &[]).0, 0x182);
}

#[test]
fn ecc_keys_sign_and_restricted_ones_only_what_the_tpm_hashed() {
    let (mut tpm, _) = started();
    let (srk, _) = primary(&mut tpm, RH_OWNER, KERNEL_TEMPLATE);
    let (key, public) = child(&mut tpm, srk, ECC_KEY_TEMPLATE);
    let point =
        [&[4u8][..], &public[public.len() - 66..public.len() - 34], &public[public.len() - 32..]]
            .concat();
    let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    let digest = sha256(&[b"to be signed"]);
    let (code, sig) = sign(&mut tpm, key, &digest, &[0x00, 0x18, 0x00, 0x0B], &NULL_TICKET);
    assert_eq!(code, 0, "ECDSA");
    assert_eq!(sig[..4], [0x00, 0x18, 0x00, 0x0B]);
    let r = &sig[6..6 + u16_at(&sig, 4) as usize];
    let s = &sig[8 + r.len()..];
    let sig = p256::ecdsa::Signature::from_scalars(
        <[u8; 32]>::try_from(r).unwrap(),
        <[u8; 32]>::try_from(s).unwrap(),
    )
    .unwrap();
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    verifier.verify_prehash(&digest, &sig).expect("ECDSA verifies");
    // An ECC key does not do RSA's schemes: TPM_RC_SCHEME on the scheme.
    assert_eq!(sign(&mut tpm, key, &digest, &[0x00, 0x14, 0x00, 0x0B], &NULL_TICKET).0, 0x2D2);

    let flush = command(0x8001, 0x165, &[], None, &key.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &flush)), 0);
    let (ak, _) = child(&mut tpm, srk, RESTRICTED_ECC_TEMPLATE);
    // A restricted key signs only a digest the TPM made, with the ticket to prove it:
    // TPM_RC_TICKET on the validation without one.
    assert_eq!(sign(&mut tpm, ak, &digest, &[0x00, 0x10], &NULL_TICKET).0, 0x3E0);
    let hash = |tpm: &mut Janus<Recorder>, data: &[u8]| {
        let params = [tpm2b(data), vec![0, 0x0B], RH_OWNER.to_be_bytes().to_vec()].concat();
        let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x17D, &[], None, &params));
        assert_eq!(rc(&rsp), 0);
        (rsp[12..44].to_vec(), rsp[44..].to_vec())
    };
    let (d, ticket) = hash(&mut tpm, b"to be signed");
    assert_eq!(d, digest);
    assert_eq!(sign(&mut tpm, ak, &d, &[0x00, 0x10], &ticket).0, 0);
    // The ticket is for that digest only.
    let other = sha256(&[b"something else"]);
    assert_eq!(sign(&mut tpm, ak, &other, &[0x00, 0x10], &ticket).0, 0x3E0);
    // Data that starts like an attestation gets no ticket, so it cannot be signed.
    let (d, ticket) = hash(&mut tpm, b"\xffTCG forged quote");
    assert_eq!(sign(&mut tpm, ak, &d, &[0x00, 0x10], &ticket).0, 0x3E0);
}

/// Randomness for the test's own encryptions.
struct Rng(u8);

impl rand_core::TryRng for Rng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for b in dst {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Rng {}

#[test]
fn a_session_salted_to_an_rsa_key_derives_the_key_the_client_does() {
    let (mut tpm, _) = started();
    let (srk, public) = primary(&mut tpm, RH_OWNER, RSA_SRK_TEMPLATE);
    let salt = [0x5A; 32];
    let encrypted = rsa_public(&public)
        .encrypt(&mut Rng(1), rsa::Oaep::<Sha256>::new_with_label(&b"SECRET\0"[..]), &salt)
        .unwrap();
    let nonce_caller = vec![0xC3; 32];
    let params = [
        tpm2b(&nonce_caller),
        tpm2b(&encrypted),
        vec![0x00],
        AES_128_CFB.to_vec(),
        SHA256.to_be_bytes().to_vec(),
    ]
    .concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x176, &[srk, RH_NULL], None, &params));
    assert_eq!(rc(&rsp), 0, "StartAuthSession");
    let n = u16_at(&rsp, 14) as usize;
    let nonce_tpm = rsp[16..16 + n].to_vec();
    let key = kdfa(&salt, "ATH", &nonce_tpm, &nonce_caller, 256);
    let mut s = Session { handle: u32_at(&rsp, 10), key, nonce_caller, nonce_tpm };

    // GetRandom under it: the response HMAC verifies under the key derived from the salt.
    let params = 16u16.to_be_bytes();
    let cp = sha256(&[&0x17Bu32.to_be_bytes(), &params]);
    let area = s.entry(&cp, CONTINUE | ENCRYPT, &[]);
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x17B, &[], Some(&area), &params));
    assert_eq!(rc(&rsp), 0, "GetRandom");
    let size = u32_at(&rsp, 10) as usize;
    let rp = sha256(&[&0u32.to_be_bytes(), &0x17Bu32.to_be_bytes(), &rsp[14..14 + size]]);
    s.check(&rp, CONTINUE | ENCRYPT, &[], &rsp[14 + size..]);

    // A salt encrypted under another label does not decrypt: TPM_RC_VALUE on the salt.
    let wrong = rsa_public(&public)
        .encrypt(&mut Rng(2), rsa::Oaep::<Sha256>::new_with_label(&b"SECRET"[..]), &salt)
        .unwrap();
    let params = [
        tpm2b(&[0xC3; 32]),
        tpm2b(&wrong),
        vec![0x00],
        AES_128_CFB.to_vec(),
        SHA256.to_be_bytes().to_vec(),
    ]
    .concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x176, &[srk, RH_NULL], None, &params));
    assert_eq!(rc(&rsp), 0x2C4);
}

/// A password session whose password is `pw`.
fn pw(pw: &[u8]) -> Vec<u8> {
    [&RS_PW.to_be_bytes()[..], &[0, 0, 0], &tpm2b(pw)].concat()
}

fn sequence_update(tpm: &mut Janus<Recorder>, seq: u32, auth: &[u8], data: &[u8]) -> u32 {
    rc(&tpm.execute(Locality::ZERO, &command(0x8002, 0x15C, &[seq], Some(&pw(auth)), &tpm2b(data))))
}

/// TPM2_SequenceComplete; returns the code, the digest and the ticket.
fn sequence_complete(
    tpm: &mut Janus<Recorder>,
    seq: u32,
    auth: &[u8],
    data: &[u8],
) -> (u32, Vec<u8>, Vec<u8>) {
    let params = [tpm2b(data), RH_OWNER.to_be_bytes().to_vec()].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x13E, &[seq], Some(&pw(auth)), &params));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new(), Vec::new());
    }
    let size = u32_at(&rsp, 10) as usize;
    let out = &rsp[14..14 + size];
    (0, out[2..34].to_vec(), out[34..].to_vec())
}

fn start_sequence(tpm: &mut Janus<Recorder>, auth: &[u8], alg: u16) -> u32 {
    let params = [tpm2b(auth), alg.to_be_bytes().to_vec()].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x186, &[], None, &params));
    assert_eq!(rc(&rsp), 0, "HashSequenceStart");
    u32_at(&rsp, 10)
}

#[test]
fn a_hash_sequence_survives_its_context_and_tickets_what_a_restricted_key_signs() {
    let (mut tpm, _) = started();
    let (srk, _) = primary(&mut tpm, RH_OWNER, KERNEL_TEMPLATE);
    let (ak, _) = child(&mut tpm, srk, RESTRICTED_ECC_TEMPLATE);
    let flush = command(0x8001, 0x165, &[], None, &srk.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &flush)), 0);

    let message: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let seq = start_sequence(&mut tpm, b"seq", 0x000B);
    assert_eq!(sequence_update(&mut tpm, seq, b"seq", &message[..70]), 0);
    // A resource manager saves the sequence between commands and loads it back.
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x162, &[seq], None, &[]));
    assert_eq!(rc(&rsp), 0, "ContextSave");
    let context = rsp[10..].to_vec();
    assert_eq!(
        rc(&tpm.execute(Locality::ZERO, &command(0x8001, 0x165, &[], None, &seq.to_be_bytes()))),
        0
    );
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x161, &[], None, &context));
    assert_eq!(rc(&rsp), 0, "ContextLoad");
    let seq = u32_at(&rsp, 10);
    // Its authValue came back with it; a wrong one is BAD_AUTH, and a sequence is exempt
    // from dictionary-attack protection, so it does not count.
    assert_eq!(sequence_update(&mut tpm, seq, b"sex", &message[70..150]), 0x9A2);
    assert_eq!(sequence_update(&mut tpm, seq, b"seq", &message[70..150]), 0);
    let (code, digest, ticket) = sequence_complete(&mut tpm, seq, b"seq", &message[150..]);
    assert_eq!(code, 0, "SequenceComplete");
    assert_eq!(digest, sha256(&[&message]));
    assert_eq!(ticket[..6], [0x80, 0x24, 0x40, 0x00, 0x00, 0x01], "an owner hierarchy ticket");
    // The restricted key signs the digest with that ticket.
    assert_eq!(sign(&mut tpm, ak, &digest, &[0x00, 0x10], &ticket).0, 0);
    // SequenceComplete flushed the sequence.
    assert_eq!(sequence_update(&mut tpm, seq, b"seq", b"more"), 0x910);

    // A first block too short to tell whether it starts like an attestation: no ticket.
    let seq = start_sequence(&mut tpm, b"", 0x000B);
    assert_eq!(sequence_update(&mut tpm, seq, b"", b"\xffTC"), 0);
    let (_, digest, ticket) = sequence_complete(&mut tpm, seq, b"", b"G quote");
    assert_eq!(digest, sha256(&[b"\xffTCG quote"]));
    assert_eq!(ticket, NULL_TICKET.to_vec());
    // With no update, the final block decides.
    let seq = start_sequence(&mut tpm, b"", 0x000B);
    assert_eq!(sequence_complete(&mut tpm, seq, b"", b"\xffTCG quote").2, NULL_TICKET.to_vec());

    // A key is not a sequence: TPM_RC_MODE on the handle, after it authorized.
    assert_eq!(sequence_update(&mut tpm, ak, b"", b"data"), 0x189);
    // An event sequence updates, but only EventSequenceComplete ends it: TPM_RC_MODE.
    let event = start_sequence(&mut tpm, b"", 0x0010);
    assert_eq!(sequence_update(&mut tpm, event, b"", b"data"), 0);
    assert_eq!(sequence_complete(&mut tpm, event, b"", b"").0, 0x189);
    // A sequence is not a key: TPM_RC_SEQUENCE.
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x173, &[event], None, &[]));
    assert_eq!(rc(&rsp), 0x103);
    // No hash janus does not implement: TPM_RC_HASH on the algorithm.
    let params = [tpm2b(b""), 0x000Cu16.to_be_bytes().to_vec()].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x186, &[], None, &params));
    assert_eq!(rc(&rsp), 0x2C3);
}

fn evict(tpm: &mut Janus<Recorder>, auth: u32, object: u32, persistent: u32) -> u32 {
    let c = command(0x8002, 0x120, &[auth, object], Some(&pw_area()), &persistent.to_be_bytes());
    rc(&tpm.execute(Locality::ZERO, &c))
}

fn read_public(tpm: &mut Janus<Recorder>, h: u32) -> Vec<u8> {
    tpm.execute(Locality::ZERO, &command(0x8001, 0x173, &[h], None, &[]))
}

fn flush(tpm: &mut Janus<Recorder>, h: u32) {
    let c = command(0x8001, 0x165, &[], None, &h.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &c)), 0, "FlushContext {h:#x}");
}

/// TPM2_GetCapability(HANDLES, 0x81000000).
fn persistent_handles(tpm: &mut Janus<Recorder>) -> Vec<u32> {
    let params = [1u32, 0x8100_0000, 16].map(u32::to_be_bytes).concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x17A, &[], None, &params));
    assert_eq!(rc(&rsp), 0);
    (0..u32_at(&rsp, 15) as usize).map(|i| u32_at(&rsp, 19 + 4 * i)).collect()
}

/// TPM2_Create under `parent` with an empty authValue; returns the private and public areas,
/// each as its TPM2B.
fn create_blob(tpm: &mut Janus<Recorder>, parent: u32, template: &str) -> (u32, Vec<u8>) {
    let params =
        [tpm2b(&[0, 0, 0, 0]), tpm2b(&hex(template)), vec![0, 0], vec![0, 0, 0, 0]].concat();
    let rsp =
        tpm.execute(Locality::ZERO, &command(0x8002, 0x153, &[parent], Some(&pw_area()), &params));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new());
    }
    let n = u16_at(&rsp, 14) as usize;
    let m = u16_at(&rsp, 16 + n) as usize;
    (0, rsp[14..18 + n + m].to_vec())
}

const SRK: u32 = 0x8100_0001;

#[test]
fn a_secret_sealed_under_a_persistent_key_unseals_after_a_reset() {
    let (mut tpm, _) = started();
    let (srk, public) = primary(&mut tpm, RH_OWNER, KERNEL_TEMPLATE);
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, SRK), 0);
    flush(&mut tpm, srk);
    assert_eq!(persistent_handles(&mut tpm), [SRK]);
    // The persistent object is the same object: the same public area.
    let rsp = read_public(&mut tpm, SRK);
    assert_eq!(rc(&rsp), 0);
    assert_eq!(rsp[12..12 + public.len()], public[..]);

    // Sealed under the persistent key, as systemd-cryptenroll does (tests/corpus/03).
    let (item, _, private, sealed) = seal(&mut tpm, SRK, b"pw", &[], b"volume key", USER_WITH_AUTH);
    flush(&mut tpm, item);

    // A TPM Reset: everything transient is gone, the persistent key is not.
    let shutdown = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x45, 0, 0];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &shutdown)), 0, "Shutdown");
    tpm.init();
    let startup = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup)), 0);
    assert_eq!(persistent_handles(&mut tpm), [SRK]);
    let params = [tpm2b(&private), tpm2b(&sealed)].concat();
    let load = command(0x8002, 0x157, &[SRK], Some(&pw_area()), &params);
    let rsp = tpm.execute(Locality::ZERO, &load);
    assert_eq!(rc(&rsp), 0, "Load under the persistent key");
    let item = u32_at(&rsp, 10);
    let unseal_pw = [RS_PW.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 2], b"pw".to_vec()].concat();
    let rsp = tpm.execute(Locality::ZERO, &command(0x8002, 0x15E, &[item], Some(&unseal_pw), &[]));
    assert_eq!(rc(&rsp), 0, "Unseal");
    assert_eq!(rsp[16..26], *b"volume key");

    // EvictControl of the persistent object at its own handle removes it.
    assert_eq!(evict(&mut tpm, RH_OWNER, SRK, SRK), 0);
    assert_eq!(persistent_handles(&mut tpm), []);
    // A persistent handle that names nothing: TPM_RC_HANDLE on the handle.
    assert_eq!(rc(&read_public(&mut tpm, SRK)), 0x18B);
}

#[test]
fn evict_control_refuses_in_the_reference_order() {
    let (mut tpm, _) = started();
    let (srk, _) = primary(&mut tpm, RH_OWNER, KERNEL_TEMPLATE);
    // TPMI_DH_PERSISTENT: VALUE on the parameter.
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, 0x8000_0000), 0x1C4);
    // TPMI_RH_PROVISION: VALUE on the first handle.
    assert_eq!(evict(&mut tpm, 0x4000_000B, srk, SRK), 0x184);
    // The owner's handles are below 0x81800000: RANGE on the parameter.
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, 0x8180_0000), 0x1CD);
    // The platform may not persist an owner object: HIERARCHY on the object.
    assert_eq!(evict(&mut tpm, 0x4000_000C, srk, 0x8180_0000), 0x285);
    // A NULL-hierarchy object cannot outlive a reset: ATTRIBUTES on the object.
    let (null, _) = primary(&mut tpm, RH_NULL, KERNEL_TEMPLATE);
    assert_eq!(evict(&mut tpm, RH_OWNER, null, SRK), 0x282);
    flush(&mut tpm, null);
    // A handle in use: TPM_RC_NV_DEFINED.
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, SRK), 0);
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, SRK), 0x14C);
    // A persistent object named by another handle: HANDLE on the object.
    assert_eq!(evict(&mut tpm, RH_OWNER, SRK, SRK + 1), 0x28B);
    // Seven persistent objects at most: TPM_RC_NV_SPACE.
    for i in 1..7 {
        assert_eq!(evict(&mut tpm, RH_OWNER, srk, SRK + i), 0, "{i}");
    }
    assert_eq!(evict(&mut tpm, RH_OWNER, srk, SRK + 7), 0x14B);
    flush(&mut tpm, srk);

    // A persistent object takes a free transient slot for the command, as the reference
    // copies it into one (`ObjectLoadEvict`).
    let (code, blob) = create_blob(&mut tpm, SRK, ECC_KEY_TEMPLATE);
    assert_eq!(code, 0);
    let (a, _) = primary(&mut tpm, RH_NULL, KERNEL_TEMPLATE);
    let (b, _) = primary(&mut tpm, RH_NULL, KERNEL_TEMPLATE);
    // Two slots taken: naming the persistent key fills the third, and Create or Load has no
    // room for its own object.
    assert_eq!(rc(&read_public(&mut tpm, SRK)), 0);
    assert_eq!(create_blob(&mut tpm, SRK, ECC_KEY_TEMPLATE).0, 0x902);
    let load = command(0x8002, 0x157, &[SRK], Some(&pw_area()), &blob);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &load)), 0x902);
    // Three taken: naming it at all is TPM_RC_OBJECT_MEMORY, before TPM_RC_HANDLE.
    let (c, _) = primary(&mut tpm, RH_NULL, KERNEL_TEMPLATE);
    assert_eq!(rc(&read_public(&mut tpm, SRK)), 0x902);
    assert_eq!(rc(&read_public(&mut tpm, 0x8100_0100)), 0x902);
    for h in [a, b, c] {
        flush(&mut tpm, h);
    }
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &load)), 0);
}

/// A password session whose password is `pw`, as an authorization area.
fn pw_auth(pw: &[u8]) -> Vec<u8> {
    [&RS_PW.to_be_bytes()[..], &[0, 0, 0], &tpm2b(pw)].concat()
}

/// TPMS_NV_PUBLIC for a SHA-256 index.
fn nv_public(index: u32, attributes: u32, policy: &[u8], size: u16) -> Vec<u8> {
    [
        &index.to_be_bytes()[..],
        &[0, 0x0B],
        &attributes.to_be_bytes(),
        &tpm2b(policy),
        &size.to_be_bytes(),
    ]
    .concat()
}

fn nv_define(tpm: &mut Janus<Recorder>, by: u32, auth: &[u8], public: &[u8]) -> u32 {
    let params = [tpm2b(auth), tpm2b(public)].concat();
    rc(&tpm.execute(Locality::ZERO, &command(0x8002, 0x12A, &[by], Some(&pw_area()), &params)))
}

fn nv_write(
    tpm: &mut Janus<Recorder>,
    by: u32,
    index: u32,
    pw: &[u8],
    data: &[u8],
    offset: u16,
) -> u32 {
    let params = [tpm2b(data), offset.to_be_bytes().to_vec()].concat();
    let c = command(0x8002, 0x137, &[by, index], Some(&pw_auth(pw)), &params);
    rc(&tpm.execute(Locality::ZERO, &c))
}

fn nv_extend(tpm: &mut Janus<Recorder>, by: u32, index: u32, pw: &[u8], data: &[u8]) -> u32 {
    let c = command(0x8002, 0x136, &[by, index], Some(&pw_auth(pw)), &tpm2b(data));
    rc(&tpm.execute(Locality::ZERO, &c))
}

/// TPM2_NV_Read; returns the code and the data.
fn nv_read(
    tpm: &mut Janus<Recorder>,
    by: u32,
    index: u32,
    pw: &[u8],
    size: u16,
    offset: u16,
) -> (u32, Vec<u8>) {
    let params = [size.to_be_bytes(), offset.to_be_bytes()].concat();
    let rsp = tpm.execute(
        Locality::ZERO,
        &command(0x8002, 0x14E, &[by, index], Some(&pw_auth(pw)), &params),
    );
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new());
    }
    let n = u16_at(&rsp, 14) as usize;
    (0, rsp[16..16 + n].to_vec())
}

/// TPM2_NV_ReadPublic; returns the public area and the name.
fn nv_read_public(tpm: &mut Janus<Recorder>, index: u32) -> (u32, Vec<u8>, Vec<u8>) {
    let rsp = tpm.execute(Locality::ZERO, &command(0x8001, 0x169, &[index], None, &[]));
    if rc(&rsp) != 0 {
        return (rc(&rsp), Vec::new(), Vec::new());
    }
    let n = u16_at(&rsp, 10) as usize;
    let m = u16_at(&rsp, 12 + n) as usize;
    (0, rsp[12..12 + n].to_vec(), rsp[14 + n..14 + n + m].to_vec())
}

fn power_cycle(tpm: &mut Janus<Recorder>, shutdown_state: bool, startup_state: bool) {
    let shutdown = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x45, 0, shutdown_state as u8];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &shutdown)), 0, "Shutdown");
    tpm.init();
    let startup = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, startup_state as u8];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup)), 0, "Startup");
}

/// systemd-pcrlock's indexes (`tests/corpus/01-tpm2-setup`): owner-defined, extended under
/// their own empty authValue, ORDERLY and CLEAR_STCLEAR, so they read like a PCR that starts
/// over at every Startup(CLEAR).
#[test]
fn a_pcrlock_index_extends_like_a_pcr_and_starts_over_at_startup_clear() {
    let (mut tpm, _) = started();
    // The guest's own commands, byte for byte.
    let define = hex(
        "80020000002d0000012a40000001000000094000000900000000000000000e01d10201000b0c06004600000020",
    );
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &define)), 0, "NV_DefineSpace");
    let extend = hex("8002000000410000013601d1020101d10201000000094000000900000000000020\
         697863029fdeb0ec64251db7acf3df4a663c2f5fcb7a5a27078d3556cff235aa");
    let index = 0x01D1_0201;
    let (_, before, name_before) = nv_read_public(&mut tpm, index);
    assert_eq!(before, nv_public(index, 0x0C06_0046, &[], 32));
    assert_eq!(name_before, [&[0, 0x0B][..], &sha256(&[&before])].concat());
    // Unwritten: TPM_RC_NV_UNINITIALIZED.
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0).0, 0x14A);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &extend)), 0, "NV_Extend");
    let d1 = &extend[extend.len() - 32..];
    let once = sha256(&[&[0u8; 32][..], d1]);
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0), (0, once.clone()));
    // Written now: TPMA_NV_WRITTEN is set, and the name follows the public area.
    let (_, after, name_after) = nv_read_public(&mut tpm, index);
    assert_eq!(after, nv_public(index, 0x2C06_0046, &[], 32));
    assert_eq!(name_after, [&[0, 0x0B][..], &sha256(&[&after])].concat());
    // The owner may read it too (OWNERREAD), but a read of more than it holds is NV_RANGE.
    assert_eq!(nv_read(&mut tpm, RH_OWNER, index, b"", 16, 16), (0, once[16..].to_vec()));
    assert_eq!(nv_read(&mut tpm, RH_OWNER, index, b"", 32, 1).0, 0x146);
    assert_eq!(nv_extend(&mut tpm, index, index, b"", b"more"), 0);
    let twice = sha256(&[&once, b"more"]);
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0), (0, twice.clone()));
    // An extend index takes no NV_Write (TPM_RC_ATTRIBUTES).
    assert_eq!(nv_write(&mut tpm, index, index, b"", &[1; 32], 0), 0x082);

    // A Resume keeps it; a Restart starts it over, and an extend starts from zeros again.
    power_cycle(&mut tpm, true, true);
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0), (0, twice));
    power_cycle(&mut tpm, true, false);
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0).0, 0x14A);
    assert_eq!(nv_extend(&mut tpm, index, index, b"", d1), 0);
    assert_eq!(nv_read(&mut tpm, index, index, b"", 32, 0), (0, once));

    // The index is ORDERLY, kept in RAM and saved at Shutdown: extending it after a
    // Shutdown(STATE) makes that saved state stale, and the Resume is refused (VALUE).
    let shutdown = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x45, 0, 1];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &shutdown)), 0);
    assert_eq!(nv_extend(&mut tpm, index, index, b"", d1), 0);
    tpm.init();
    let resume = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 1];
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &resume)), 0x1C4);
}

#[test]
fn an_ordinary_index_holds_what_was_written_under_its_own_password() {
    let (mut tpm, _) = started();
    let index = 0x0150_0000;
    // OWNERWRITE | AUTHWRITE | OWNERREAD | AUTHREAD.
    let public = nv_public(index, 0x0006_0006, &[], 64);
    assert_eq!(nv_define(&mut tpm, RH_OWNER, b"secret", &public), 0);
    assert_eq!(nv_write(&mut tpm, index, index, b"secret", b"hello", 5), 0);
    let mut expected = vec![0u8; 64];
    expected[5..10].copy_from_slice(b"hello");
    assert_eq!(nv_read(&mut tpm, index, index, b"secret", 64, 0), (0, expected));
    // A wrong password for the index, which counts toward lockout: AUTH_FAIL on the session.
    assert_eq!(nv_read(&mut tpm, index, index, b"wrong", 64, 0).0, 0x98E);
    // An offset past the end is VALUE on it; data past the end is NV_RANGE.
    assert_eq!(nv_write(&mut tpm, index, index, b"secret", b"x", 65), 0x2C4);
    assert_eq!(nv_write(&mut tpm, index, index, b"secret", b"xy", 63), 0x146);
    assert_eq!(nv_read(&mut tpm, index, index, b"secret", 1025, 0).0, 0x1C4);
    // Another index authorizes, then is refused: TPM_RC_NV_AUTHORIZATION.
    let other = 0x0150_0001;
    assert_eq!(nv_define(&mut tpm, RH_OWNER, b"", &nv_public(other, 0x0006_0006, &[], 8)), 0);
    assert_eq!(nv_read(&mut tpm, other, index, b"", 8, 0).0, 0x149);
    // An index whose own authValue may not read it (no AUTHREAD): AUTH_UNAVAILABLE.
    let owner_read = 0x0150_0002;
    assert_eq!(nv_define(&mut tpm, RH_OWNER, b"", &nv_public(owner_read, 0x0002_0004, &[], 8)), 0);
    assert_eq!(nv_write(&mut tpm, owner_read, owner_read, b"", b"12345678", 0), 0);
    assert_eq!(nv_read(&mut tpm, owner_read, owner_read, b"", 8, 0).0, 0x12F);
    assert_eq!(nv_read(&mut tpm, RH_OWNER, owner_read, b"", 8, 0), (0, b"12345678".to_vec()));
    // The owner may not read or write an index that gives it neither: NV_AUTHORIZATION.
    let own = 0x0150_0003;
    assert_eq!(nv_define(&mut tpm, RH_OWNER, b"", &nv_public(own, 0x0004_0004, &[], 8)), 0);
    assert_eq!(nv_write(&mut tpm, RH_OWNER, own, b"", b"12345678", 0), 0x149);
    assert_eq!(nv_write(&mut tpm, own, own, b"", b"12345678", 0), 0);
    assert_eq!(nv_read(&mut tpm, RH_OWNER, own, b"", 8, 0).0, 0x149);
    // The platform may not, without PPREAD.
    assert_eq!(nv_read(&mut tpm, 0x4000_000C, index, b"", 8, 0).0, 0x149);
    // Undefined by the owner; then it names nothing (HANDLE on the index's handle).
    let undefine = command(0x8002, 0x122, &[RH_OWNER, index], Some(&pw_area()), &[]);
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &undefine)), 0);
    assert_eq!(nv_read(&mut tpm, RH_OWNER, index, b"", 8, 0).0, 0x28B);
    assert_eq!(nv_read_public(&mut tpm, index).0, 0x18B);
}

#[test]
fn nv_define_space_refuses_in_the_reference_order() {
    let (mut tpm, _) = started();
    let ok = 0x0006_0006;
    let extend = ok | 0x40;
    let mut define = |by: u32, auth: &[u8], public: Vec<u8>| nv_define(&mut tpm, by, auth, &public);
    // TPMI_RH_NV_INDEX in the public area: VALUE on it; a reserved TPMA_NV bit: RESERVED_BITS.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x8100_0000, ok, &[], 8)), 0x2C4);
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok | 0x100, &[], 8)), 0x2E1);
    // A policy that is not a digest: SIZE on the public area.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok, &[1; 20], 8)), 0x2D5);
    // An authValue longer than the digest: SIZE on the authValue.
    assert_eq!(define(RH_OWNER, &[1; 33], nv_public(0x0150_0000, ok, &[], 8)), 0x1D5);
    // A counter, which janus does not implement: ATTRIBUTES on the public area.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok | 0x10, &[], 8)), 0x2C2);
    // An extend index the size of no digest: SIZE.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, extend, &[], 20)), 0x2D5);
    // Written already, unreadable, unwritable: ATTRIBUTES.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok | 1 << 29, &[], 8)), 0x2C2);
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, 0x0000_0006, &[], 8)), 0x2C2);
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, 0x0006_0000, &[], 8)), 0x2C2);
    // The platform's index made by the owner: ATTRIBUTES on the authorization handle.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok | 1 << 30, &[], 8)), 0x182);
    // Defined twice: TPM_RC_NV_DEFINED.
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok, &[], 8)), 0);
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000, ok, &[], 8)), 0x14C);
    // Sixty-four indexes at most: TPM_RC_NV_SPACE.
    for i in 1..64 {
        assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0000 + i, ok, &[], 8)), 0, "{i}");
    }
    assert_eq!(define(RH_OWNER, b"", nv_public(0x0150_0040, ok, &[], 8)), 0x14B);
}
