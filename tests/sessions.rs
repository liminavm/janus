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

use std::cell::RefCell;
use std::rc::Rc;

use aes::cipher::KeyIvInit;
use hmac::{KeyInit, Mac};
use janus::{Janus, Locality, Platform};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest as _, Sha256};

/// Deterministic randomness that remembers what it gave, so a test can check what GetRandom
/// encrypted.
#[derive(Clone)]
struct Recorder {
    next: Rc<RefCell<u8>>,
    given: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl Platform for Recorder {
    fn fill_random(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            let mut n = self.next.borrow_mut();
            *n = n.wrapping_add(1);
            *b = *n;
        }
        self.given.borrow_mut().push(buf.to_vec());
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
    let platform = Recorder { next: Rc::default(), given: Rc::default() };
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
