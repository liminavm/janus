// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exhaustive walks of small state machines against a model kept outside the engine.
//!
//! Every sequence of operations up to a fixed depth is run on a fresh TPM, and each step's
//! response is checked against what the model says it must be. Each walk also asserts it
//! reached the cases it exists for, so a change that makes a branch unreachable fails here
//! rather than passing vacuously.

use janus::{Janus, Locality, Platform, SelfTests};
use sha2::{Digest as _, Sha256};

struct Zero;

impl Platform for Zero {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
    // The walks reset the TPM hundreds of thousands of times and test no cryptography.
    fn self_tests(&mut self) -> SelfTests {
        SelfTests::Skip
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

/// A platform whose clock the walk advances.
struct Clocked(std::rc::Rc<std::cell::Cell<u64>>);

impl Platform for Clocked {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        self.0.get()
    }
    // The walks reset the TPM hundreds of thousands of times and test no cryptography.
    fn self_tests(&mut self) -> SelfTests {
        SelfTests::Skip
    }
}

const OWNER: u32 = 0x4000_0001;
const LOCKOUT: u32 = 0x4000_000A;
/// An NV index with the password `pin`, subject to dictionary-attack protection.
const INDEX: u32 = 0x0150_0000;
const RC_AUTH_FAIL: u32 = 0x98E;
const RC_LOCKOUT: u32 = 0x921;
const RC_NV_UNINITIALIZED: u32 = 0x14A;

fn password_area(pw: &[u8]) -> Vec<u8> {
    let entry =
        [&0x4000_0009u32.to_be_bytes()[..], &[0, 0, 0], &(pw.len() as u16).to_be_bytes(), pw]
            .concat();
    [&(entry.len() as u32).to_be_bytes()[..], &entry].concat()
}

/// NV_Read of the index under its own password: TPM_RC_NV_UNINITIALIZED once authorized.
fn read_index(pw: &[u8]) -> Vec<u8> {
    let body = [&INDEX.to_be_bytes()[..], &INDEX.to_be_bytes(), &password_area(pw), &[0, 8, 0, 0]]
        .concat();
    cmd(0x8002, 0x14E, &body)
}

fn lock_reset(pw: &[u8]) -> Vec<u8> {
    cmd(0x8002, 0x139, &[&LOCKOUT.to_be_bytes()[..], &password_area(pw)].concat())
}

#[derive(Clone, Copy, Debug)]
enum DaOp {
    Init,
    Startup,
    Shutdown,
    WrongPin,
    RightPin,
    WrongLockout,
    LockReset,
    /// 600 s pass on the platform clock.
    Wait,
}

const DA_OPS: [DaOp; 8] = [
    DaOp::Init,
    DaOp::Startup,
    DaOp::Shutdown,
    DaOp::WrongPin,
    DaOp::RightPin,
    DaOp::WrongLockout,
    DaOp::LockReset,
    DaOp::Wait,
];

/// The reference's `DA.c` and `IncrementLockout`, with its manufactured parameters: 3 tries,
/// 1000 s per healed failure, 1000 s for the lockout hierarchy.
#[derive(Clone, Copy)]
struct DaModel {
    running: bool,
    /// A Shutdown since the last Startup.
    orderly: bool,
    failed: u32,
    lockout_enabled: bool,
    /// The platform clock, and its reading at `_TPM_Init`; `Time` is the difference.
    clock: u64,
    init_at: u64,
    heal_timer: u64,
    lockout_timer: u64,
}

impl DaModel {
    const MAX: u32 = 3;
    const RECOVERY_MS: u64 = 1_000_000;

    fn time(&self) -> u64 {
        self.clock - self.init_at
    }

    /// `DASelfHeal`, before every command.
    fn heal(&mut self) {
        let time = self.time();
        let healed = time.saturating_sub(self.heal_timer) / Self::RECOVERY_MS;
        if self.failed != 0 {
            self.failed = self.failed.saturating_sub(healed as u32);
            self.heal_timer += healed * Self::RECOVERY_MS;
        }
        if !self.lockout_enabled && time.saturating_sub(self.lockout_timer) >= Self::RECOVERY_MS {
            self.lockout_enabled = true;
        }
    }
}

#[derive(Default)]
struct DaReached {
    locked_out: bool,
    healed: bool,
    lockout_recovered: bool,
    unorderly_counted: bool,
    counted_to_the_limit_only: bool,
    reset: bool,
}

/// Every sequence of six dictionary-attack operations from a started TPM holding a protected
/// index, against the model: each response code, and after each command the lockout counter
/// and `inLockout`.
#[test]
fn dictionary_attack_lockout() {
    const DEPTH: u32 = 6;
    let mut reached = DaReached::default();
    for n in 0..DA_OPS.len().pow(DEPTH) {
        let clock = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut tpm = Janus::manufacture(Clocked(clock.clone()));
        tpm.init();
        assert_eq!(rc(&tpm.execute(Locality::ZERO, &startup(false))), 0);
        let public = [&INDEX.to_be_bytes()[..], &[0, 0x0B, 0, 6, 0, 6, 0, 0, 0, 8]].concat();
        let define = [
            &OWNER.to_be_bytes()[..],
            &password_area(b""),
            &[0, 3],
            b"pin",
            &(public.len() as u16).to_be_bytes(),
            &public,
        ]
        .concat();
        assert_eq!(rc(&tpm.execute(Locality::ZERO, &cmd(0x8002, 0x12A, &define))), 0);
        let mut m = DaModel {
            running: true,
            orderly: false,
            failed: 0,
            lockout_enabled: true,
            clock: 0,
            init_at: 0,
            heal_timer: 0,
            lockout_timer: 0,
        };
        let mut k = n;
        let mut trace = Vec::new();
        for _ in 0..DEPTH {
            let op = DA_OPS[k % DA_OPS.len()];
            k /= DA_OPS.len();
            trace.push(op);
            da_step(&mut tpm, &clock, &mut m, op, &mut reached, &trace);
        }
    }
    assert!(reached.locked_out, "never refused a right PIN in lockout");
    assert!(reached.healed, "never healed a failure with time");
    assert!(reached.lockout_recovered, "never recovered the lockout hierarchy with time");
    assert!(reached.unorderly_counted, "never counted a Startup after no shutdown");
    assert!(reached.counted_to_the_limit_only, "never held an unorderly Startup at the limit");
    assert!(reached.reset, "never cleared the count with DictionaryAttackLockReset");
}

fn da_step(
    tpm: &mut Janus<Clocked>,
    clock: &std::rc::Rc<std::cell::Cell<u64>>,
    m: &mut DaModel,
    op: DaOp,
    reached: &mut DaReached,
    trace: &[DaOp],
) {
    let loc = Locality::ZERO;
    let fail = |what: &str| -> ! { panic!("{what} after {trace:?}") };
    let command = match op {
        DaOp::Init => {
            tpm.init();
            m.running = false;
            m.init_at = m.clock;
            return;
        }
        DaOp::Wait => {
            m.clock += 600_000;
            clock.set(m.clock);
            return;
        }
        DaOp::Startup => startup(false),
        DaOp::Shutdown => shutdown(false),
        DaOp::WrongPin => read_index(b"no"),
        DaOp::RightPin => read_index(b"pin"),
        DaOp::WrongLockout => lock_reset(b"no"),
        DaOp::LockReset => lock_reset(b""),
    };
    let r = rc(&tpm.execute(loc, &command));
    if !m.running {
        if !matches!(op, DaOp::Startup) {
            if r != RC_INITIALIZE {
                fail("a command before Startup was not refused");
            }
            return;
        }
        if r != 0 {
            fail("Startup failed");
        }
        // `DAStartup`: the timers restart, and a Startup after no shutdown counts a failure.
        m.running = true;
        m.heal_timer = 0;
        m.lockout_timer = 0;
        if !m.orderly {
            reached.unorderly_counted |= m.failed < DaModel::MAX;
            reached.counted_to_the_limit_only |= m.failed == DaModel::MAX;
            m.failed = (m.failed + 1).min(DaModel::MAX);
        }
        m.orderly = false;
        m.heal();
    } else {
        let before = (m.failed, m.lockout_enabled);
        m.heal();
        reached.healed |= m.failed < before.0;
        let recovered = m.lockout_enabled && !before.1;
        let expected = match op {
            DaOp::Startup => RC_INITIALIZE,
            DaOp::Shutdown => {
                m.orderly = true;
                0
            }
            DaOp::WrongPin | DaOp::RightPin if m.failed >= DaModel::MAX => {
                reached.locked_out |= matches!(op, DaOp::RightPin);
                RC_LOCKOUT
            }
            DaOp::WrongPin => {
                m.failed += 1;
                m.heal_timer = m.time();
                RC_AUTH_FAIL
            }
            DaOp::RightPin => RC_NV_UNINITIALIZED,
            DaOp::WrongLockout | DaOp::LockReset if !m.lockout_enabled => RC_LOCKOUT,
            DaOp::WrongLockout => {
                m.lockout_enabled = false;
                m.lockout_timer = m.time();
                RC_AUTH_FAIL
            }
            DaOp::LockReset => {
                reached.reset |= m.failed > 0;
                reached.lockout_recovered |= recovered;
                m.failed = 0;
                0
            }
            DaOp::Init | DaOp::Wait => unreachable!(),
        };
        if r != expected {
            fail(&format!("{op:?} answered {r:#x}, the model {expected:#x}"));
        }
    }
    // The counter and inLockout, as GetCapability reports them.
    let rsp = tpm.execute(loc, &cmd(0x8001, 0x17A, &[0, 0, 0, 6, 0, 0, 0x02, 0x0E, 0, 0, 0, 1]));
    assert!(rsp.len() >= 27, "{rsp:02x?} after {trace:?}");
    let counter = u32::from_be_bytes(rsp[23..27].try_into().unwrap());
    let rsp = tpm.execute(loc, &cmd(0x8001, 0x17A, &[0, 0, 0, 6, 0, 0, 0x02, 0x00, 0, 0, 0, 1]));
    let in_lockout = u32::from_be_bytes(rsp[23..27].try_into().unwrap()) & 1 << 9 != 0;
    m.heal();
    if counter != m.failed || in_lockout != (m.failed >= DaModel::MAX) {
        fail(&format!(
            "the counter reads {counter} (inLockout {in_lockout}), the model {}",
            m.failed
        ));
    }
}
