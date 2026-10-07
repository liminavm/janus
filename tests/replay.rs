// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replays command streams captured from real guests against swtpm (libtpms 0.10.2) and checks
//! janus answers the way the guest relied on.
//!
//! The corpus is `tests/corpus/*.jsonl`, captured by limina's `spikes/vtpm-p0` (QEMU, edk2 and
//! stock Fedora 44 against swtpm with one SHA-256 PCR bank). Each line is a command with
//! swtpm's response, or a control event: `init` is `_TPM_Init` (a platform reset), `locality`
//! sets the locality of the commands after it.
//!
//! A replay runs until the first command janus does not implement, or the first one an HMAC or
//! policy session authorizes: such a session is salted to swtpm's key, whose private part only
//! swtpm has, so its HMACs cannot verify against janus. `tests/sessions.rs` takes over from
//! there with a client of its own. Each test states how far the replay must get.
//!
//! Most responses must match byte for byte. The exceptions are where the two TPMs differ by
//! design, each handled by name in [`compare`]: vendor properties, the command list, the PCR
//! update counter, the hash algorithms only swtpm implements, and everything derived from a
//! TPM's own secrets (a primary key, a saved context, a ticket), which is compared by shape.
//! A command that hands back one of swtpm's saved contexts gets janus's instead ([`adapt`]).

use janus::{Janus, Locality, Platform};
use serde_json::Value;

/// Deterministic randomness: GetRandom's bytes are not compared, only their length.
struct Counter(u8);

impl Platform for Counter {
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

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

const SHA256: u16 = 0x000B;

enum Event {
    Init,
    Locality(u8),
    Command { cc: String, cmd: Vec<u8>, rsp: Vec<u8> },
}

fn load(name: &str) -> Vec<Event> {
    let path = format!("{}/tests/corpus/{name}.jsonl", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            match v.get("ctrl").and_then(Value::as_str) {
                Some("init") => Event::Init,
                Some("locality") => Event::Locality(v["value"].as_u64().unwrap() as u8),
                Some(other) => panic!("unknown control event {other}"),
                None => Event::Command {
                    cc: v["cc"].as_str().unwrap().to_owned(),
                    cmd: hex(v["cmd"].as_str().unwrap()),
                    rsp: hex(v["rsp"].as_str().unwrap()),
                },
            }
        })
        .collect()
}

/// The commands janus implements, by the decoder's names.
const IMPLEMENTED: &[&str] = &[
    "HierarchyChangeAuth",
    "CreatePrimary",
    "ContextLoad",
    "ContextSave",
    "FlushContext",
    "ReadPublic",
    "StartAuthSession",
    "SelfTest",
    "Startup",
    "Shutdown",
    "GetCapability",
    "GetRandom",
    "PCR_Read",
    "PCR_Extend",
];

/// Handles in each implemented command's handle area, to find its authorization area.
fn handle_count(cc: &str) -> usize {
    match cc {
        "StartAuthSession" => 2,
        "HierarchyChangeAuth" | "CreatePrimary" | "PCR_Extend" | "ReadPublic" | "ContextSave" => 1,
        _ => 0,
    }
}

/// Whether a session other than a password authorizes or encrypts this command.
fn uses_a_session(cc: &str, cmd: &[u8]) -> bool {
    if u16_at(cmd, 0) != 0x8002 {
        return false;
    }
    let at = 10 + 4 * handle_count(cc);
    let end = at + 4 + u32_at(cmd, at) as usize;
    let mut i = at + 4;
    while i < end {
        if u32_at(cmd, i) != 0x4000_0009 {
            return true;
        }
        let nonce = u16_at(cmd, i + 4) as usize;
        let hmac = u16_at(cmd, i + 7 + nonce) as usize;
        i += 9 + nonce + hmac;
    }
    false
}

/// The saved contexts the two TPMs gave for the same ContextSave: swtpm's, then janus's.
type Contexts = Vec<(Vec<u8>, Vec<u8>)>;

/// Replays `name` from a freshly manufactured TPM until the first unimplemented command or the
/// first one a session authorizes, returning how many commands were compared and why it
/// stopped.
fn replay(name: &str) -> (usize, Option<String>) {
    let mut tpm = Janus::manufacture(Counter(0));
    let mut locality = Locality::ZERO;
    let mut compared = 0;
    let mut started = false;
    let mut contexts: Contexts = Vec::new();
    for (i, e) in load(name).into_iter().enumerate() {
        match e {
            Event::Init => {
                tpm.init();
                started = true;
            }
            Event::Locality(l) => locality = Locality::new(l).unwrap(),
            // QEMU probes swtpm before powering it on; that answer is swtpm's, not a TPM's.
            Event::Command { .. } if !started => {}
            Event::Command { cc, cmd, rsp } => {
                if !IMPLEMENTED.contains(&cc.as_str()) {
                    return (compared, Some(cc));
                }
                if uses_a_session(&cc, &cmd) {
                    return (compared, Some(format!("{cc} under a session")));
                }
                let ours = tpm.execute(locality, &adapt(&cc, &cmd, &contexts));
                if cc == "ContextSave" && u32_at(&ours, 6) == 0 && u32_at(&rsp, 6) == 0 {
                    contexts.push((rsp[10..].to_vec(), ours[10..].to_vec()));
                }
                if let Err(why) = compare(&cc, &cmd, &ours, &rsp) {
                    panic!(
                        "{name}:{} {cc}: {why}\n  command  {}\n  swtpm    {}\n  janus    {}",
                        i + 1,
                        hexs(&cmd),
                        hexs(&rsp),
                        hexs(&ours)
                    );
                }
                compared += 1;
            }
        }
    }
    (compared, None)
}

/// The command the guest would have sent janus, where it differs from what it sent swtpm.
///
/// A ContextLoad of a context swtpm saved loads the one janus saved at the same point.
///
/// edk2 sizes the random platform authorization by the largest digest among the banks
/// `TPM_CAP_PCRS` lists (`GetAuthSize`, `PeiDxeTpmPlatformHierarchyLib.c`): 64 for swtpm, which
/// lists SHA-512, and 32 for janus. Its 64-byte value is cut to the 32 bytes it would have sent.
fn adapt(cc: &str, cmd: &[u8], contexts: &Contexts) -> Vec<u8> {
    if cc == "ContextLoad" {
        let Some((_, ours)) = contexts.iter().rev().find(|(theirs, _)| *theirs == cmd[10..]) else {
            return cmd.to_vec();
        };
        let mut out = cmd[..10].to_vec();
        out.extend_from_slice(ours);
        let len = out.len() as u32;
        out[2..6].copy_from_slice(&len.to_be_bytes());
        return out;
    }
    if cc != "HierarchyChangeAuth" {
        return cmd.to_vec();
    }
    // header (10), authHandle (4), authorizationSize (4), the area, newAuth
    let area = u32_at(cmd, 14) as usize;
    let at = 18 + area;
    let size = u16_at(cmd, at) as usize;
    if size <= 32 {
        return cmd.to_vec();
    }
    let mut out = cmd[..at].to_vec();
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(&cmd[at + 2..at + 2 + 32]);
    let len = out.len() as u32;
    out[2..6].copy_from_slice(&len.to_be_bytes());
    out
}

/// What swtpm took and janus must refuse: a platform authorization longer than any digest
/// janus implements.
#[test]
fn a_platform_auth_longer_than_any_digest_is_refused() {
    let boot = load("boot");
    let Some(Event::Command { cmd, .. }) =
        boot.iter().find(|e| matches!(e, Event::Command { cc, .. } if cc == "HierarchyChangeAuth"))
    else {
        panic!("the boot corpus has no HierarchyChangeAuth");
    };
    let mut tpm = Janus::manufacture(Counter(0));
    tpm.init();
    let startup = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0];
    assert_eq!(rc_of(&tpm.execute(Locality::ZERO, &startup)), 0);
    // TPM_RC_SIZE on parameter 1.
    assert_eq!(rc_of(&tpm.execute(Locality::ZERO, cmd)), 0x1d5);
    assert_eq!(
        rc_of(&tpm.execute(Locality::ZERO, &adapt("HierarchyChangeAuth", cmd, &Vec::new()))),
        0
    );
}

fn rc_of(rsp: &[u8]) -> u32 {
    u32_at(rsp, 6)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn compare(cc: &str, cmd: &[u8], ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    let rc = |b: &[u8]| u32_at(b, 6);
    if rc(theirs) != 0 || rc(ours) != 0 {
        return if ours == theirs {
            Ok(())
        } else {
            Err(format!("response code {:#05x}, swtpm {:#05x}", rc(ours), rc(theirs)))
        };
    }
    match cc {
        "GetCapability" => compare_capability(u32_at(cmd, 10), ours, theirs),
        // The update counter starts where each implementation's PCR table puts it; the
        // selection and the values must agree.
        "PCR_Read" => {
            if ours[..10] == theirs[..10] && ours[14..] == theirs[14..] {
                Ok(())
            } else {
                Err("PCR values or selection differ".into())
            }
        }
        "CreatePrimary" => compare_create_primary(ours, theirs),
        "ContextSave" => compare_context(ours, theirs),
        // A session handle and a nonce as long as the caller's.
        "StartAuthSession" => {
            if ours.len() == theirs.len() && ours[..16] == theirs[..16] {
                Ok(())
            } else {
                Err("a different session handle or nonce size".into())
            }
        }
        // Random bytes: the same shape.
        "GetRandom" => {
            if ours.len() == theirs.len() && ours[..12] == theirs[..12] {
                Ok(())
            } else {
                Err("a different number of random bytes".into())
            }
        }
        _ if ours == theirs => Ok(()),
        _ => Err("responses differ".into()),
    }
}

/// Splits a TPM2B off the front of `b`.
fn tpm2b(b: &[u8]) -> (&[u8], &[u8]) {
    let n = u16_at(b, 0) as usize;
    (&b[2..2 + n], &b[2 + n..])
}

/// CreatePrimary: the same handle, the same public area but for the key janus generated from
/// its own seed, the same creation data and creation hash (which depend only on the command
/// and the PCRs), a ticket for the same hierarchy, and a name of the same algorithm.
fn compare_create_primary(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), handle (4), parameterSize (4)
    if ours[10..14] != theirs[10..14] {
        return Err("a different object handle".into());
    }
    let (o, t) = (&ours[18..], &theirs[18..]);
    let (o_public, o) = tpm2b(o);
    let (t_public, t) = tpm2b(t);
    // An ECC public area ends with its point: two 32-byte coordinates, each a TPM2B.
    let template = |p: &[u8]| p[..p.len() - 68].to_vec();
    if o_public.len() != t_public.len() || template(o_public) != template(t_public) {
        return Err("the public areas differ beyond the key".into());
    }
    let (o_creation, o) = tpm2b(o);
    let (t_creation, t) = tpm2b(t);
    if o_creation != t_creation {
        return Err("the creation data differ".into());
    }
    let (o_hash, o) = tpm2b(o);
    let (t_hash, t) = tpm2b(t);
    if o_hash != t_hash {
        return Err("the creation hashes differ".into());
    }
    // TPMT_TK_CREATION: tag, hierarchy, digest (swtpm's is SHA-512, janus's SHA-256).
    if o[..6] != t[..6] {
        return Err("the ticket's tag or hierarchy differ".into());
    }
    let (_, o) = tpm2b(&o[6..]);
    let (_, t) = tpm2b(&t[6..]);
    let (o_name, o) = tpm2b(o);
    let (t_name, t) = tpm2b(t);
    if o_name.len() != t_name.len() || o_name[..2] != t_name[..2] {
        return Err("the names differ in shape".into());
    }
    if o != t {
        return Err("the authorization areas differ".into());
    }
    Ok(())
}

/// ContextSave: the same sequence, saved handle and hierarchy; the blob is each TPM's own.
fn compare_context(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), sequence (8), savedHandle (4), hierarchy (4), contextBlob
    if ours[10..26] == theirs[10..26] {
        Ok(())
    } else {
        Err("a different sequence, saved handle or hierarchy".into())
    }
}

fn compare_capability(capability: u32, ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), moreData (1), capability (4), count (4), entries
    let entries = |b: &[u8], width: usize| -> Vec<Vec<u8>> {
        let n = u32_at(b, 15) as usize;
        (0..n).map(|i| b[19 + i * width..19 + (i + 1) * width].to_vec()).collect()
    };
    match capability {
        // Commands: every TPMA_CC janus reports must be swtpm's for the same command; swtpm
        // implements more, so janus's list is shorter and may skip ahead.
        2 => {
            let theirs = entries(theirs, 4);
            for e in entries(ours, 4) {
                let code = u32_at(&e, 0) & 0xFFFF;
                let same = theirs.iter().find(|t| u32_at(t, 0) & 0xFFFF == code);
                if same.is_some_and(|t| *t != e) {
                    return Err(format!("TPMA_CC for {code:#x} differs"));
                }
            }
            Ok(())
        }
        // PCR allocation: swtpm lists every hash it implements (empty if unallocated); janus
        // implements one. The SHA-256 bank must be the same.
        5 => {
            let bank = |b: &[u8]| -> Option<Vec<u8>> {
                let n = u32_at(b, 15) as usize;
                let mut at = 19;
                for _ in 0..n {
                    let size = b[at + 2] as usize;
                    let entry = b[at..at + 3 + size].to_vec();
                    if u16_at(b, at) == SHA256 {
                        return Some(entry);
                    }
                    at += 3 + size;
                }
                None
            };
            if bank(ours).is_some() && bank(ours) == bank(theirs) && u32_at(ours, 15) == 1 {
                Ok(())
            } else {
                Err("the SHA-256 bank differs".into())
            }
        }
        // Properties: the same properties in the same order, and the same values except the
        // ones that describe the implementation rather than the interface.
        6 => {
            const VENDOR: &[u32] = &[
                0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109, 0x10A, 0x10B, 0x10C, 0x11A,
                0x120, 0x121, 0x122, 0x125, 0x128, 0x129, 0x12A,
            ];
            let (o, t) = (entries(ours, 8), entries(theirs, 8));
            if o.len() != t.len() || ours[10] != theirs[10] {
                return Err("a different number of properties".into());
            }
            for (o, t) in o.iter().zip(&t) {
                let tag = u32_at(o, 0);
                if tag != u32_at(t, 0) {
                    return Err(format!("property {tag:#x} where swtpm has {:#x}", u32_at(t, 0)));
                }
                if !VENDOR.contains(&tag) && o != t {
                    return Err(format!("property {tag:#x} differs"));
                }
            }
            Ok(())
        }
        other => Err(format!("capability {other} is not compared yet")),
    }
}

/// edk2 and the kernel's first commands: two boots (a firmware reset in between), every PCR
/// measurement and the platform hierarchy's new authorization, then the kernel's null primary
/// key, saved, flushed and loaded back, and the salted session it starts with that key, up to
/// the first command that session protects.
#[test]
fn a_boot_replays_up_to_the_kernels_first_session() {
    let (compared, stopped) = replay("boot");
    assert_eq!(stopped.as_deref(), Some("GetRandom under a session"));
    assert_eq!(compared, 264, "the boot prefix grew or shrank");
}

/// A guest reboot: the kernel's Shutdown, _TPM_Init, the firmware's whole measured boot, and the
/// next kernel's null primary key and session.
#[test]
fn a_reboot_replays_up_to_the_kernels_first_session() {
    let (compared, stopped) = replay("09-reboot");
    assert_eq!(stopped.as_deref(), Some("GetRandom under a session"));
    assert!(compared > 136, "only {compared} commands replayed");
}
