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
//! there with a client of its own. Two exceptions keep the kernel's commands replaying: its
//! encrypted GetRandom is skipped (nothing in it can be compared, and it changes nothing), and
//! its PCR_Extend is resent under a password (a PCR's authorization is empty). Each test states
//! how far the replay must get; [`the_corpus_replays_as_one_run`] is the ledger for the whole
//! corpus.
//!
//! Most responses must match byte for byte. The exceptions are where the two TPMs differ by
//! design, each handled by name in [`compare`]: vendor properties, the command list, the PCR
//! update counter, the hash algorithms only swtpm implements, and everything derived from a
//! TPM's own secrets (a primary key, a saved context, a ticket), which is compared by shape.
//! A command that hands back what swtpm made (a saved context, a key's blobs, a hashcheck
//! ticket) gets what janus made for the same command instead ([`adapt`]).

#[path = "support/watchdog.rs"]
mod watchdog;

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

/// The commands janus implements, by the decoder's names: every one the corpus holds.
const IMPLEMENTED: &[&str] = &[
    "ContextLoad",
    "ContextSave",
    "Create",
    "CreatePrimary",
    "ECC_Parameters",
    "EvictControl",
    "FlushContext",
    "GetCapability",
    "GetRandom",
    "Hash",
    "HashSequenceStart",
    "HierarchyChangeAuth",
    "Load",
    "NV_DefineSpace",
    "NV_Extend",
    "PCR_Extend",
    "PCR_Read",
    "PolicyAuthValue",
    "PolicyGetDigest",
    "PolicyPCR",
    "RSA_Decrypt",
    "ReadClock",
    "ReadPublic",
    "SelfTest",
    "SequenceComplete",
    "SequenceUpdate",
    "Shutdown",
    "Sign",
    "StartAuthSession",
    "Startup",
    "TestParms",
    "Unseal",
];

/// Handles in each implemented command's handle area, to find its authorization area.
fn handle_count(cc: &str) -> usize {
    match cc {
        "StartAuthSession" | "EvictControl" | "NV_Extend" => 2,
        "HierarchyChangeAuth"
        | "CreatePrimary"
        | "PCR_Extend"
        | "ReadPublic"
        | "ContextSave"
        | "Create"
        | "Load"
        | "Unseal"
        | "Sign"
        | "RSA_Decrypt"
        | "SequenceUpdate"
        | "SequenceComplete"
        | "PolicyPCR"
        | "PolicyAuthValue"
        | "PolicyGetDigest"
        | "NV_DefineSpace" => 1,
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

/// What the two TPMs gave for the same command, swtpm's then janus's, where a later command
/// hands it back: a saved context, a key's private and public areas (each a TPM2B), or a
/// hashcheck ticket.
type Contexts = Vec<(Vec<u8>, Vec<u8>)>;

/// Replays `name` from a freshly manufactured TPM until the first unimplemented command or the
/// first one a session authorizes, returning how many commands were compared and why it
/// stopped (`None`: it ran to the end).
fn replay(name: &str) -> (usize, Option<String>) {
    let mut tpm = Janus::manufacture(Counter(0));
    replay_into(&mut tpm, name, &mut Vec::new())
}

/// Replays `name` into `tpm` as [`replay`] does. A capture that starts with the TPM already
/// running (no `_TPM_Init` before its first command) is compared from its first command.
fn replay_into(
    tpm: &mut Janus<Counter>,
    name: &str,
    contexts: &mut Contexts,
) -> (usize, Option<String>) {
    let events = load(name);
    let mut locality = Locality::ZERO;
    let mut compared = 0;
    // Joined mid-run, the TPM has run commands this replay never sent.
    let joined = !events.iter().any(|e| matches!(e, Event::Init));
    let started_here = !joined;
    let mut started = joined;
    for (i, e) in events.into_iter().enumerate() {
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
                let under_session = uses_a_session(&cc, &cmd);
                let cmd = match cc.as_str() {
                    // The kernel's random bytes, encrypted to its session: nothing to compare,
                    // and no state changes.
                    "GetRandom" if under_session => continue,
                    // A PCR's authorization is empty: the same extend under a password.
                    "PCR_Extend" if under_session => with_password(&cmd),
                    _ if under_session => {
                        return (compared, Some(format!("{cc} under a session")));
                    }
                    _ => cmd,
                };
                // A blob swtpm made in a command the chain never replayed: janus has no
                // counterpart to hand over.
                if joined && cc == "Load" {
                    let at = 18 + u32_at(&cmd, 14) as usize;
                    let private = tpm2b_whole(&cmd[at..]).0;
                    if !contexts.iter().any(|(t, _)| t == private) {
                        return (
                            compared,
                            Some(format!("{cc} of what an unreplayed command made")),
                        );
                    }
                }
                let ours = tpm.execute(locality, &adapt(&cc, &cmd, contexts));
                // Its response carries swtpm's session HMAC; only the code compares.
                if under_session {
                    assert_eq!(u32_at(&ours, 6), u32_at(&rsp, 6), "{name}:{} {cc}", i + 1);
                    compared += 1;
                    continue;
                }
                // Joined mid-run, a handle swtpm held and janus does not was made by a command
                // the chain never replayed (the unreplayed rest of an earlier capture).
                let missing = |rc: u32| (0x910..=0x916).contains(&rc) || rc & 0x0BF == 0x08B;
                if joined && u32_at(&rsp, 6) == 0 && missing(u32_at(&ours, 6)) {
                    return (compared, Some(format!("{cc} of what an unreplayed command made")));
                }
                if cc == "ContextSave" && u32_at(&ours, 6) == 0 && u32_at(&rsp, 6) == 0 {
                    contexts.push((rsp[10..].to_vec(), ours[10..].to_vec()));
                }
                // SequenceComplete's ticket: what follows the digest in the parameter area.
                if cc == "SequenceComplete" && u32_at(&ours, 6) == 0 && u32_at(&rsp, 6) == 0 {
                    let ticket = |r: &[u8]| {
                        let end = 14 + u32_at(r, 10) as usize;
                        r[14 + 2 + u16_at(r, 14) as usize..end].to_vec()
                    };
                    contexts.push((ticket(&rsp), ticket(&ours)));
                }
                // Create's outPrivate and outPublic, after the parameter size.
                if cc == "Create" && u32_at(&ours, 6) == 0 && u32_at(&rsp, 6) == 0 {
                    let (t_private, t) = tpm2b_whole(&rsp[14..]);
                    let (o_private, o) = tpm2b_whole(&ours[14..]);
                    contexts.push((t_private.to_vec(), o_private.to_vec()));
                    contexts.push((tpm2b_whole(t).0.to_vec(), tpm2b_whole(o).0.to_vec()));
                }
                if let Err(why) = compare(&cc, &cmd, &ours, &rsp, !started_here) {
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
///
/// swtpm lists its unallocated banks in `TPM_CAP_PCRS` with empty selections, and a guest that
/// reads every listed bank sends PCR_Read an empty selection for each; janus lists only its
/// SHA-256 bank, so the guest would not. Those empty selections are dropped.
fn adapt(cc: &str, cmd: &[u8], contexts: &Contexts) -> Vec<u8> {
    if cc == "PCR_Read" {
        let mut out = cmd[..10].to_vec();
        out.extend_from_slice(&without_empty_banks(&cmd[10..]));
        let len = out.len() as u32;
        out[2..6].copy_from_slice(&len.to_be_bytes());
        return out;
    }
    // Sign's validation, its last parameter: the ticket janus gave for the same digest.
    if cc == "Sign" {
        if let Some((theirs, ours)) = contexts.iter().rev().find(|(t, _)| cmd.ends_with(t)) {
            let mut out = cmd[..cmd.len() - theirs.len()].to_vec();
            out.extend_from_slice(ours);
            let len = out.len() as u32;
            out[2..6].copy_from_slice(&len.to_be_bytes());
            return out;
        }
        return cmd.to_vec();
    }
    // Load: the key janus made for the same Create.
    if cc == "Load" {
        let at = 18 + u32_at(cmd, 14) as usize;
        let (private, rest) = tpm2b_whole(&cmd[at..]);
        let (public, rest) = tpm2b_whole(rest);
        let swap = |b: &[u8]| -> Vec<u8> {
            contexts
                .iter()
                .rev()
                .find(|(t, _)| *t == b)
                .map_or_else(|| b.to_vec(), |(_, o)| o.clone())
        };
        let mut out = cmd[..at].to_vec();
        out.extend_from_slice(&swap(private));
        out.extend_from_slice(&swap(public));
        out.extend_from_slice(rest);
        let len = out.len() as u32;
        out[2..6].copy_from_slice(&len.to_be_bytes());
        return out;
    }
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

/// `cmd` (one handle) with its authorization area replaced by an empty password.
fn with_password(cmd: &[u8]) -> Vec<u8> {
    let area = u32_at(cmd, 14) as usize;
    let mut out = cmd[..14].to_vec();
    out.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
    out.extend_from_slice(&cmd[18 + area..]);
    let len = out.len() as u32;
    out[2..6].copy_from_slice(&len.to_be_bytes());
    out
}

/// A `TPML_PCR_SELECTION` (and whatever follows it) without the empty selections of banks
/// other than SHA-256.
fn without_empty_banks(b: &[u8]) -> Vec<u8> {
    let n = u32_at(b, 0) as usize;
    let mut kept = Vec::new();
    let mut at = 4;
    for _ in 0..n {
        let size = b[at + 2] as usize;
        let entry = &b[at..at + 3 + size];
        if u16_at(b, at) == SHA256 || entry[3..].iter().any(|x| *x != 0) {
            kept.push(entry.to_vec());
        }
        at += 3 + size;
    }
    let mut out = (kept.len() as u32).to_be_bytes().to_vec();
    kept.iter().for_each(|e| out.extend_from_slice(e));
    out.extend_from_slice(&b[at..]);
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

/// `joined`: the capture began with the TPM already running, so counters that every earlier
/// command advanced (a context's sequence) can differ.
fn compare(cc: &str, cmd: &[u8], ours: &[u8], theirs: &[u8], joined: bool) -> Result<(), String> {
    let rc = |b: &[u8]| u32_at(b, 6);
    if rc(theirs) != 0 || rc(ours) != 0 {
        return if ours == theirs {
            Ok(())
        } else {
            Err(format!("response code {:#05x}, swtpm {:#05x}", rc(ours), rc(theirs)))
        };
    }
    match cc {
        "GetCapability" => compare_capability(u32_at(cmd, 10), ours, theirs, joined),
        // The update counter starts where each implementation's PCR table puts it; the
        // selection and the values must agree.
        // A capture joined mid-run follows extends the guest made between captures, so its PCR
        // values are compared only in their shape: the selection and the digest sizes.
        "PCR_Read" => {
            let theirs = [&theirs[..14], &without_empty_banks(&theirs[14..])[..]].concat();
            let selection = 18 + 6 * u32_at(ours, 14) as usize;
            let same = if joined {
                ours.len() == theirs.len() && ours[14..selection] == theirs[14..selection]
            } else {
                ours[10..].len() == theirs[10..].len() && ours[14..] == theirs[14..]
            };
            if same { Ok(()) } else { Err("PCR values or selection differ".into()) }
        }
        "CreatePrimary" => compare_create_primary(ours, theirs),
        "Create" => compare_create(ours, theirs),
        "SequenceComplete" => compare_sequence_complete(ours, theirs),
        // A signature by each TPM's own key: the same scheme, hash and size.
        "Sign" | "RSA_Decrypt" if ours.len() == theirs.len() && ours[..18] == theirs[..18] => {
            Ok(())
        }
        "Sign" | "RSA_Decrypt" => Err("the signature differs in shape".into()),
        "Load" => compare_load(ours, theirs),
        "ReadPublic" => compare_read_public(ours, theirs),
        "ContextSave" => compare_context(ours, theirs, joined),
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

/// Splits a TPM2B, size included, off the front of `b`.
fn tpm2b_whole(b: &[u8]) -> (&[u8], &[u8]) {
    let n = 2 + u16_at(b, 0) as usize;
    (&b[..n], &b[n..])
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
    let (o, t) = compare_creation(&ours[18..], &theirs[18..], false)?;
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

/// Create: outPrivate is each TPM's own; the rest as CreatePrimary's.
fn compare_create(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), parameterSize (4), outPrivate
    let (_, o) = tpm2b(&ours[14..]);
    let (_, t) = tpm2b(&theirs[14..]);
    let (o, t) = compare_creation(o, t, true)?;
    if o != t {
        return Err("the authorization areas differ".into());
    }
    Ok(())
}

/// SequenceComplete: the same digest, and a ticket for the same hierarchy (its HMAC is swtpm's
/// SHA-512 and janus's SHA-256, under each TPM's own proof).
fn compare_sequence_complete(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), parameterSize (4), result, validation (tag, hierarchy, digest)
    let (o_result, o) = tpm2b(&ours[14..]);
    let (t_result, t) = tpm2b(&theirs[14..]);
    if o_result != t_result {
        return Err("the digests differ".into());
    }
    if o[..6] != t[..6] {
        return Err("the ticket's tag or hierarchy differ".into());
    }
    let (_, o) = tpm2b(&o[6..]);
    let (_, t) = tpm2b(&t[6..]);
    if o != t {
        return Err("the authorization areas differ".into());
    }
    Ok(())
}

/// Load: the same handle, and a name of the same shape.
fn compare_load(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), handle (4), parameterSize (4), name
    if ours[10..14] != theirs[10..14] {
        return Err("a different object handle".into());
    }
    let (o_name, o) = tpm2b(&ours[18..]);
    let (t_name, t) = tpm2b(&theirs[18..]);
    if o_name.len() != t_name.len() || o_name[..2] != t_name[..2] || o != t {
        return Err("the names differ in shape".into());
    }
    Ok(())
}

/// outPublic, creationData, creationHash and creationTicket, as CreatePrimary and Create give
/// them: the same template and key size, the same creation data and hash (which depend only on
/// the command and the PCRs), and a ticket for the same hierarchy. Returns what follows.
///
/// A key's parent is a key (`keyed_parent`) under Create: the creation data then name it, and
/// its name is each TPM's own, so the names compare by shape and the hash over them by size.
fn compare_creation<'a>(
    o: &'a [u8],
    t: &'a [u8],
    keyed_parent: bool,
) -> Result<(&'a [u8], &'a [u8]), String> {
    let (o_public, o) = tpm2b(o);
    let (t_public, t) = tpm2b(t);
    if o_public.len() != t_public.len() || template(o_public) != template(t_public) {
        return Err("the public areas differ beyond the key".into());
    }
    let (o_creation, o) = tpm2b(o);
    let (t_creation, t) = tpm2b(t);
    let same_creation = if keyed_parent {
        creation_without_names(o_creation) == creation_without_names(t_creation)
    } else {
        o_creation == t_creation
    };
    if !same_creation {
        return Err("the creation data differ".into());
    }
    let (o_hash, o) = tpm2b(o);
    let (t_hash, t) = tpm2b(t);
    if if keyed_parent { o_hash.len() != t_hash.len() } else { o_hash != t_hash } {
        return Err("the creation hashes differ".into());
    }
    // TPMT_TK_CREATION: tag, hierarchy, digest (swtpm's is SHA-512, janus's SHA-256).
    if o[..6] != t[..6] {
        return Err("the ticket's tag or hierarchy differ".into());
    }
    let (_, o) = tpm2b(&o[6..]);
    let (_, t) = tpm2b(&t[6..]);
    Ok((o, t))
}

/// TPMS_CREATION_DATA with the parent's name and qualified name reduced to their shape.
fn creation_without_names(c: &[u8]) -> Vec<u8> {
    // pcrSelect (a TPML_PCR_SELECTION), pcrDigest, locality, parentNameAlg, parentName,
    // parentQualifiedName, outsideInfo
    let mut at = 4;
    for _ in 0..u32_at(c, 0) {
        at += 3 + c[at + 2] as usize;
    }
    at += 2 + u16_at(c, at) as usize + 1 + 2;
    let mut out = c[..at].to_vec();
    let (name, rest) = tpm2b(&c[at..]);
    let (qualified, rest) = tpm2b(rest);
    for n in [name, qualified] {
        out.extend_from_slice(&(n.len() as u16).to_be_bytes());
        out.extend_from_slice(n.get(..2).unwrap_or_default());
    }
    out.extend_from_slice(rest);
    out
}

/// A public area without its unique field, which is each TPM's own key.
fn template(public: &[u8]) -> Option<&[u8]> {
    let unique = match u16_at(public, 0) {
        0x0023 => 68,          // ECC: two 32-byte coordinates, each a TPM2B
        0x0001 => 258,         // RSA-2048: the modulus
        0x0008 | 0x0025 => 34, // KEYEDHASH, SYMCIPHER: a SHA-256 digest
        _ => return None,
    };
    public.get(..public.len().checked_sub(unique)?)
}

/// ReadPublic of a key both TPMs made: the same template and key size, and names of the same
/// shape.
fn compare_read_public(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    // header (10), outPublic, name, qualifiedName
    let (o_public, o) = tpm2b(&ours[10..]);
    let (t_public, t) = tpm2b(&theirs[10..]);
    if o_public.len() != t_public.len() || template(o_public) != template(t_public) {
        return Err("the public areas differ beyond the key".into());
    }
    let (o_name, o) = tpm2b(o);
    let (t_name, t) = tpm2b(t);
    let (o_qualified, _) = tpm2b(o);
    let (t_qualified, _) = tpm2b(t);
    let shape = |n: &[u8]| (n.len(), n.get(..2).map(<[u8]>::to_vec));
    if shape(o_name) != shape(t_name) || shape(o_qualified) != shape(t_qualified) {
        return Err("the names differ in shape".into());
    }
    Ok(())
}

/// ContextSave: the same sequence (unless `joined`), saved handle and hierarchy; the blob is each
/// TPM's own.
fn compare_context(ours: &[u8], theirs: &[u8], joined: bool) -> Result<(), String> {
    // header (10), sequence (8), savedHandle (4), hierarchy (4), contextBlob
    let from = if joined { 18 } else { 10 };
    if ours[from..26] == theirs[from..26] {
        Ok(())
    } else {
        Err("a different sequence, saved handle or hierarchy".into())
    }
}

/// `joined`: the capture began mid-run, so swtpm may hold handles an unreplayed command made.
fn compare_capability(
    capability: u32,
    ours: &[u8],
    theirs: &[u8],
    joined: bool,
) -> Result<(), String> {
    // header (10), moreData (1), capability (4), count (4), entries
    let entries = |b: &[u8], width: usize| -> Vec<Vec<u8>> {
        let n = u32_at(b, 15) as usize;
        (0..n).map(|i| b[19 + i * width..19 + (i + 1) * width].to_vec()).collect()
    };
    match capability {
        // Algorithms: every one janus lists, swtpm lists with the same attributes; swtpm
        // implements more.
        0 => {
            let theirs = entries(theirs, 6);
            match entries(ours, 6).into_iter().find(|e| !theirs.contains(e)) {
                Some(e) => Err(format!("algorithm {:#06x} differs", u16_at(&e, 0))),
                None => Ok(()),
            }
        }
        // Handles: the same; joined mid-run, a subset of swtpm's.
        1 if ours == theirs => Ok(()),
        1 if joined => {
            let theirs = entries(theirs, 4);
            match entries(ours, 4).into_iter().find(|e| !theirs.contains(e)) {
                Some(e) => Err(format!("handle {:#010x} is not swtpm's", u32_at(&e, 0))),
                None => Ok(()),
            }
        }
        1 => Err("the handles differ".into()),
        // Curves: every one janus lists, swtpm lists too; swtpm implements more.
        8 => {
            let theirs = entries(theirs, 2);
            match entries(ours, 2).into_iter().find(|e| !theirs.contains(e)) {
                Some(e) => Err(format!("curve {:#06x} is not swtpm's", u16_at(&e, 0))),
                None => Ok(()),
            }
        }
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
                0x11C, 0x120, 0x121, 0x122, 0x125, 0x128, 0x129, 0x12A,
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
/// key, saved, flushed and loaded back, the salted session it starts with that key, and the
/// commands that session protects (its encrypted GetRandom skipped, its PCR_Extend resent under
/// a password).
#[test]
fn a_boot_replays_in_full() {
    let _deadline = watchdog::watchdog(300, "the boot replay");
    assert_eq!(replay("boot"), (275, None));
}

/// A guest reboot: the kernel's Shutdown, _TPM_Init, the firmware's whole measured boot, and the
/// next kernel's null primary key and session.
#[test]
fn a_reboot_replays_in_full() {
    let _deadline = watchdog::watchdog(300, "the reboot replay");
    assert_eq!(replay("09-reboot"), (158, None));
}

/// Flushes every transient object and every loaded or saved session, as the kernel's resource
/// manager does when a client is done: a replay that stopped early never sent the client's own
/// FlushContext.
fn flush_everything(tpm: &mut Janus<Counter>) {
    for range in [0x8000_0000u32, 0x0200_0000, 0x0300_0000] {
        let cap = [
            &[0x80, 0x01, 0, 0, 0, 0x16, 0, 0, 0x01, 0x7A][..],
            &1u32.to_be_bytes(),
            &range.to_be_bytes(),
            &64u32.to_be_bytes(),
        ]
        .concat();
        let rsp = tpm.execute(Locality::ZERO, &cap);
        assert_eq!(u32_at(&rsp, 6), 0);
        for i in 0..u32_at(&rsp, 15) as usize {
            let h = u32_at(&rsp, 19 + 4 * i);
            let flush =
                [&[0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x65][..], &h.to_be_bytes()].concat();
            assert_eq!(u32_at(&tpm.execute(Locality::ZERO, &flush), 6), 0, "flush {h:#x}");
        }
    }
}

/// The whole corpus as the one run it was captured from: the boot, each consumer in turn, the
/// reboot and the consumer after it, into one TPM. A consumer's capture joins a TPM already
/// running, so its commands are compared from the first.
///
/// This is the ledger of how far the corpus replays, one stop per capture. A stop is the first
/// command an HMAC or policy session authorizes (`tests/sessions.rs` covers those), or the
/// first that uses something such a command made (a key or context swtpm holds and janus,
/// which never ran that command, does not). A change that moves a stop either way is news.
#[test]
fn the_corpus_replays_as_one_run() {
    let _deadline = watchdog::watchdog(600, "the corpus replay");
    let unreplayed = |cc: &str| Some(format!("{cc} of what an unreplayed command made"));
    let session = |cc: &str| Some(format!("{cc} under a session"));
    let ledger = [
        ("boot", 275, None),
        ("01-tpm2-setup", 58, session("Create")),
        ("02-creds", 18, session("Create")),
        ("03-cryptenroll", 15, session("Create")),
        ("04-clevis", 4, session("CreatePrimary")),
        ("05-ssh-tpm-agent", 0, unreplayed("FlushContext")),
        ("06-pkcs11", 5, session("CreatePrimary")),
        ("07-measured-boot", 16, None),
        ("08-openssl", 176, None),
        ("09-reboot", 158, None),
        ("10-after-reboot", 10, unreplayed("Load")),
    ];
    let mut tpm = Janus::manufacture(Counter(0));
    let mut contexts = Vec::new();
    for (name, compared, stop) in ledger {
        assert_eq!(replay_into(&mut tpm, name, &mut contexts), (compared, stop), "{name}");
        // A boot's sessions are the kernel's, which the next capture goes on using; a
        // consumer's objects and sessions end with it.
        if name != "boot" && name != "09-reboot" {
            flush_everything(&mut tpm);
        }
    }
}
