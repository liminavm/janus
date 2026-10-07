// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exhaustive walks of small state machines against a model kept outside the engine.
//!
//! Every sequence of operations up to a fixed depth is run on a fresh TPM, and each step's
//! response is checked against what the model says it must be. Each walk also asserts it
//! reached the cases it exists for, so a change that makes a branch unreachable fails here
//! rather than passing vacuously.

use janus::{Janus, Locality, Platform};
use sha2::{Digest as _, Sha256};

struct Zero;

impl Platform for Zero {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
}

fn cmd(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&cc.to_be_bytes());
    v.extend_from_slice(body);
    v
}

const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const RC_INITIALIZE: u32 = 0x100;
const RC_VALUE_P1: u32 = 0x1C4;

fn startup(state: bool) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x144, &[0, state as u8])
}

fn shutdown(state: bool) -> Vec<u8> {
    cmd(NO_SESSIONS, 0x145, &[0, state as u8])
}

/// The one digest every extend in these walks uses.
const DATA: [u8; 32] = [0xAB; 32];

/// PCR_Extend with an empty password session.
fn extend(pcr: u32) -> Vec<u8> {
    let mut body = pcr.to_be_bytes().to_vec();
    body.extend_from_slice(&9u32.to_be_bytes());
    body.extend_from_slice(&[0x40, 0, 0, 0x09, 0, 0, 0, 0, 0]);
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&0x000Bu16.to_be_bytes());
    body.extend_from_slice(&DATA);
    cmd(SESSIONS, 0x182, &body)
}

/// PCR_Read of PCRs 0 and 16 in the SHA-256 bank.
fn read() -> Vec<u8> {
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x00, 0x0B, 3, 0x01, 0x00, 0x01]);
    cmd(NO_SESSIONS, 0x17E, &body)
}

fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// The value of a PCR that started at zero and was extended with `DATA` `n` times.
fn chain(n: usize) -> [u8; 32] {
    let mut v = [0u8; 32];
    for _ in 0..n {
        v = Sha256::new().chain_update(v).chain_update(DATA).finalize().into();
    }
    v
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Init,
    Startup { state: bool },
    Shutdown { state: bool },
    Extend { pcr: u32 },
    Read,
}

const OPS: [Op; 8] = [
    Op::Init,
    Op::Startup { state: false },
    Op::Startup { state: true },
    Op::Shutdown { state: false },
    Op::Shutdown { state: true },
    Op::Extend { pcr: 0 },
    Op::Extend { pcr: 16 },
    Op::Read,
];

/// What the model says about the TPM. PCR 0 is state-saved, PCR 16 is not.
#[derive(Clone, Copy, Default)]
struct Model {
    running: bool,
    /// Extends of PCR 0 and PCR 16 since their last reset.
    pcr0: usize,
    pcr16: usize,
    /// PCR 0's extends when `TPM2_Shutdown(STATE)` saved it, until a Startup takes it or an
    /// extend of a state-saved PCR makes it stale (`PCR_Extend.c`, `RETURN_IF_ORDERLY`).
    saved: Option<usize>,
    /// The last Shutdown(STATE) was made stale; for the reached check only.
    stale: bool,
}

#[derive(Default)]
struct Reached {
    resumed: bool,
    resume_refused: bool,
    stale_save_refused: bool,
    restarted_after_state: bool,
    read_restored: bool,
    refused_before_startup: bool,
    refused_second_startup: bool,
}

#[test]
fn lifecycle() {
    const DEPTH: u32 = 6;
    let mut reached = Reached::default();
    let total = OPS.len().pow(DEPTH);
    for n in 0..total {
        let mut tpm = Janus::manufacture(Zero);
        let mut model = Model::default();
        let mut k = n;
        let mut trace = Vec::new();
        for _ in 0..DEPTH {
            let op = OPS[k % OPS.len()];
            k /= OPS.len();
            trace.push(op);
            step(&mut tpm, &mut model, op, &mut reached, &trace);
        }
    }
    assert!(reached.resumed, "never resumed after Shutdown(STATE)");
    assert!(reached.resume_refused, "never refused a Startup(STATE) with nothing saved");
    assert!(reached.stale_save_refused, "never refused a resume of a save made stale");
    assert!(reached.restarted_after_state, "never ran Startup(CLEAR) after Shutdown(STATE)");
    assert!(reached.read_restored, "never read a restored PCR");
    assert!(reached.refused_before_startup, "never refused a command before Startup");
    assert!(reached.refused_second_startup, "never refused a second Startup");
}

fn step(tpm: &mut Janus<Zero>, m: &mut Model, op: Op, reached: &mut Reached, trace: &[Op]) {
    let loc = Locality::ZERO;
    let fail = |what: &str| -> ! { panic!("{what} after {trace:?}") };
    match op {
        Op::Init => {
            tpm.init();
            m.running = false;
        }
        Op::Startup { state } => {
            let r = rc(&tpm.execute(loc, &startup(state)));
            if m.running {
                if r != RC_INITIALIZE {
                    fail("a second Startup was not refused");
                }
                reached.refused_second_startup = true;
                return;
            }
            let saved = m.saved.take();
            match (state, saved) {
                (true, None) => {
                    if r != RC_VALUE_P1 {
                        fail("Startup(STATE) with nothing saved was not TPM_RC_VALUE");
                    }
                    reached.resume_refused = true;
                    reached.stale_save_refused |= m.stale;
                    m.stale = false;
                }
                (true, Some(pcr0)) => {
                    if r != 0 {
                        fail("Startup(STATE) after Shutdown(STATE) failed");
                    }
                    *m = Model { running: true, pcr0, pcr16: 0, saved: None, stale: false };
                    reached.resumed = true;
                }
                (false, saved) => {
                    if r != 0 {
                        fail("Startup(CLEAR) failed");
                    }
                    reached.restarted_after_state |= saved.is_some();
                    *m = Model { running: true, pcr0: 0, pcr16: 0, saved: None, stale: false };
                }
            }
        }
        Op::Shutdown { state } => {
            let r = rc(&tpm.execute(loc, &shutdown(state)));
            if !m.running {
                if r != RC_INITIALIZE {
                    fail("Shutdown before Startup was not refused");
                }
                reached.refused_before_startup = true;
                return;
            }
            if r != 0 {
                fail("Shutdown failed");
            }
            m.saved = state.then_some(m.pcr0);
            m.stale = false;
        }
        Op::Extend { pcr } => {
            let r = rc(&tpm.execute(loc, &extend(pcr)));
            if !m.running {
                if r != RC_INITIALIZE {
                    fail("PCR_Extend before Startup was not refused");
                }
                return;
            }
            if r != 0 {
                fail("PCR_Extend failed");
            }
            match pcr {
                0 => {
                    m.pcr0 += 1;
                    m.stale |= m.saved.take().is_some();
                }
                _ => m.pcr16 += 1,
            }
        }
        Op::Read => {
            let rsp = tpm.execute(loc, &read());
            if !m.running {
                if rc(&rsp) != RC_INITIALIZE {
                    fail("PCR_Read before Startup was not refused");
                }
                return;
            }
            // header, counter, selection (4 + 2 + 1 + 3), count, two TPM2B digests
            let digests = &rsp[10 + 4 + 10 + 4..];
            let pcr0 = &digests[2..34];
            let pcr16 = &digests[36..68];
            if pcr0 != chain(m.pcr0) || pcr16 != chain(m.pcr16) {
                fail("PCR values differ from the model");
            }
            reached.read_restored |= m.pcr0 > 0 && trace.iter().any(|o| matches!(o, Op::Init));
        }
    }
}
