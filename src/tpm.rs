// SPDX-License-Identifier: MIT OR Apache-2.0

//! The engine and its lifecycle.
//!
//! After `_TPM_Init` a TPM accepts only `TPM2_Startup`; after it, everything but `TPM2_Startup`.
//! The two are different types here, [`Tpm<Initialized>`] and [`Tpm<Running>`], and only the
//! running one has PCRs, objects or a platform authorization to act on. A command that needs
//! them cannot be dispatched before Startup, because there is nothing to dispatch it to. A
//! failed self-test makes it a third, [`Tpm<Failure>`], which answers only what failure mode
//! answers until the next `_TPM_Init`.
//!
//! State lives at three lifetimes, as the reference keeps it:
//!
//! - [`Persistent`] survives everything: hierarchy authorizations and secrets, the reset count.
//! - [`ResetState`] survives `_TPM_Init` when the next Startup is a Restart or a Resume, and is
//!   made new at every TPM Reset: the null hierarchy, saved-session bookkeeping, the clear count.
//! - [`Running`] is what a power cycle loses: PCRs, loaded objects, the platform authorization.
//!
//! Which Startup a `TPM2_Startup` is follows from the last `TPM2_Shutdown`, held in
//! [`Persistent::orderly`]: `STATE` then `Startup(STATE)` is a Resume, `STATE` then
//! `Startup(CLEAR)` a Restart, anything else a Reset. A command that changes what a Shutdown
//! saved clears it (the reference's `g_clearOrderly`), so a stale save is never resumed.

use crate::alg::{Digest, Hash, MAX_DIGEST};
use crate::capability::{self, Variable};
use crate::cc::Cc;
use crate::command::{self, Command};
use crate::context::{self, Context, Epoch, SavedHandle};
use crate::crypto::{self, EccPrivate, EccPublicKey};
use crate::handle::{
    ContextHandle, EntityHandle, HierarchyAuth, ObjectHandle, PcrOrNull, handle_type, ht,
};
use crate::hierarchy::{Hierarchy, NullSecrets, PersistentSecrets, Secrets};
use crate::marshal::{List, Marshal, Tpm2b, Unmarshal};
use crate::nv::{self, NvAuth, NvPublic, NvRef, NvStore};
use crate::object::{self, Evicted, Loaded, Object, Objects, SensitiveKind, SequenceSlot};
use crate::pcr::{self, Pcrs, Selection};
use crate::rc::{At, Fmt0, Fmt1, Rc, Slot, Warn};
use crate::selftest::{self, Family, ToTest};
use crate::sequence::{self, HashSequence};
use crate::session::{
    self, AuthValue, Authorization, Authorized, Da, Entity, EntityAuth, Lockout, Session,
    SessionTable, SessionType,
};
use crate::state::{self, StateError};
use crate::types::{
    CreationData, Data2b, Digest2b, EccPoint, EccScheme, HashCheckTicket, KeyedHashScheme, Name2b,
    PublicKind, RsaDecryptScheme, RsaScheme, ST_HASHCHECK, SensitiveCreate, SigScheme, SymDef,
    TkCreation,
};
use crate::wire::{Blame as _, Buf, Reader, Writer};
use crate::{Locality, Platform};
use std::cell::Cell;
use zeroize::Zeroizing;

/// What survives `_TPM_Init`: the state a real TPM keeps in NV.
struct Persistent {
    owner_auth: AuthValue,
    endorsement_auth: AuthValue,
    lockout_auth: AuthValue,
    secrets: PersistentSecrets,
    /// TPM Resets since manufacture (`totalResetCount`). Saved contexts are bound to it. With no
    /// `TPM2_Clear` it is also the resets since the last Clear (`resetCount`), which
    /// `TPMS_CLOCK_INFO` reports.
    reset_count: u64,
    /// Milliseconds the TPM has run since manufacture (`Clock`).
    clock: u64,
    /// `TPMS_CLOCK_INFO.safe`: the clock has not been reported higher than it is. A Startup
    /// after no orderly shutdown clears it, since the clock may have been lost back to its last
    /// save; it is set again when `Clock` crosses a save boundary, as the reference sets it when
    /// it writes the clock to NV.
    clock_safe: bool,
    /// `Clock` and `safe` as NV last held them (`go`): written at manufacture, when `Clock`
    /// crosses a save boundary, and by `TPM2_Shutdown`. `_TPM_Init` starts the clock again from
    /// here, so time the TPM ran since the last save is lost unless it shut down in order.
    saved_clock: SavedClock,
    /// Objects made persistent by `TPM2_EvictControl`.
    evicted: Evicted,
    /// NV indexes.
    nv: NvStore,
    /// The last `TPM2_Shutdown`, until a Startup takes it or a command makes it stale.
    orderly: Option<Orderly>,
}

#[derive(Clone, Copy)]
struct SavedClock {
    clock: u64,
    safe: bool,
}

/// What `TPM2_Shutdown` left for the next Startup.
enum Orderly {
    Clear,
    /// The PCR bank as Shutdown(STATE) saved it; the state-saved PCRs come back from it.
    State(Box<Pcrs>),
}

/// The state a TPM Reset replaces and a Restart or Resume keeps (the reference's `gr`).
struct ResetState {
    null: NullSecrets,
    sessions: SessionTable,
    /// Restarts since the last Reset; binds the saved contexts of `stClear` objects.
    clear_count: u32,
    /// Restarts and Resumes since the last Reset (`restartCount`).
    restart_count: u32,
    /// The sequence the last saved object context got (`objectContextID`).
    object_sequence: u64,
}

impl ResetState {
    fn new(platform: &mut impl Platform) -> ResetState {
        ResetState {
            null: NullSecrets::generate(platform),
            sessions: SessionTable::default(),
            clear_count: 0,
            restart_count: 0,
            object_sequence: 0,
        }
    }
}

/// After `_TPM_Init`, before `TPM2_Startup`.
pub struct Initialized {
    /// What the TPM was running with before `_TPM_Init`, for a Restart or Resume to pick up.
    /// `None` on a newly manufactured TPM.
    carried: Option<Box<Carried>>,
}

/// After a self-test failed: the TPM answers only `TPM2_GetTestResult` and some of
/// `TPM2_GetCapability` until the next `_TPM_Init`, and changes nothing, not even its clock.
pub struct Failure {
    failed: Family,
    /// What the TPM was running with, for a Restart or Resume after the next `_TPM_Init`.
    carried: Option<Box<Carried>>,
}

struct Carried {
    platform_auth: AuthValue,
    reset: ResetState,
}

/// After `TPM2_Startup`.
pub struct Running {
    pcrs: Pcrs,
    /// Set to the empty value by every Startup but a Resume.
    platform_auth: AuthValue,
    reset: ResetState,
    objects: Objects,
    /// Slots the persistent objects this command names occupy while it runs: the reference
    /// copies each into a free transient slot for the command (`ObjectLoadEvict`).
    borrowed: Cell<usize>,
}

pub struct Tpm<S> {
    persistent: Persistent,
    clocks: Clocks,
    /// Kept apart from [`Persistent`] so the authorization check can update it while it reads
    /// an authorization value from there.
    lockout: Lockout,
    /// The algorithm families still to be self-tested since `_TPM_Init`.
    to_test: ToTest,
    stage: S,
}

/// The last platform clock reading `Clock` was advanced to, and `Time` as of it. `Time` is kept
/// rather than the reading at `_TPM_Init` so a TPM resumed on a platform whose clock started
/// again goes on from where it stood.
struct Clocks {
    last: u64,
    time: u64,
}

/// `Clock` is saved to NV when it crosses a multiple of 2^22 ms (`NV_CLOCK_UPDATE_INTERVAL`).
const CLOCK_SAVE_INTERVAL: u64 = 1 << 22;

impl<S> Tpm<S> {
    /// Advances `Clock` to the platform's `now`.
    /// `Time`: milliseconds since `_TPM_Init`.
    fn time(&self) -> u64 {
        self.clocks.time
    }

    fn tick(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.clocks.last);
        self.clocks.last = self.clocks.last.max(now);
        self.clocks.time = self.clocks.time.saturating_add(elapsed);
        let before = self.persistent.clock;
        self.persistent.clock = before.saturating_add(elapsed);
        if self.persistent.clock / CLOCK_SAVE_INTERVAL > before / CLOCK_SAVE_INTERVAL {
            self.persistent.clock_safe = true;
            self.persistent.saved_clock = SavedClock { clock: self.persistent.clock, safe: true };
        }
    }
}

enum Lifecycle {
    // Boxed, both: each carries the persistent state, and the running one its PCR bank and
    // objects too.
    Initialized(Box<Tpm<Initialized>>),
    Running(Box<Tpm<Running>>),
    Failure(Box<Tpm<Failure>>),
}

impl<S> Tpm<S> {
    /// In a snapshot, what every stage has: the persistent state as it stands (live `Clock`
    /// as well as the saved one), the lockout with its timers, `Time`, and the self-tests.
    fn write_common(&self, w: &mut Writer) {
        let p = &self.persistent;
        p.secrets.write(w);
        p.owner_auth.write(w);
        p.endorsement_auth.write(w);
        p.lockout_auth.write(w);
        w.u64(p.reset_count);
        w.u64(p.clock);
        p.clock_safe.write(w);
        w.u64(p.saved_clock.clock);
        p.saved_clock.safe.write(w);
        p.evicted.write(w);
        p.nv.save(w);
        match &p.orderly {
            None => w.u8(0),
            Some(Orderly::Clear) => w.u8(1),
            Some(Orderly::State(pcrs)) => {
                w.u8(2);
                pcrs.save(w);
            }
        }
        self.lockout.write_live(w);
        w.u64(self.time());
        self.to_test.write(w);
    }
}

fn write_reset(w: &mut Writer, reset: &ResetState) {
    reset.null.write(w);
    reset.sessions.write_live(w);
    w.u32(reset.clear_count);
    w.u32(reset.restart_count);
    w.u64(reset.object_sequence);
}

fn read_reset(r: &mut Reader<'_>) -> Result<ResetState, Fmt1> {
    Ok(ResetState {
        null: NullSecrets::read(r)?,
        sessions: SessionTable::read_live(r)?,
        clear_count: r.u32()?,
        restart_count: r.u32()?,
        object_sequence: r.u64()?,
    })
}

fn write_carried(w: &mut Writer, carried: Option<&Carried>) {
    match carried {
        None => w.u8(0),
        Some(c) => {
            w.u8(1);
            c.platform_auth.write(w);
            write_reset(w, &c.reset);
        }
    }
}

/// What a stopped TPM carries for a Restart or Resume: never a loaded session, which
/// `_TPM_Init` drops.
fn read_carried(r: &mut Reader<'_>) -> Result<Option<Box<Carried>>, Fmt1> {
    match r.u8()? {
        0 => Ok(None),
        1 => {
            let platform_auth = AuthValue::read(r)?;
            let reset = read_reset(r)?;
            if reset.sessions.has_loaded() {
                return Err(Fmt1::Value);
            }
            Ok(Some(Box::new(Carried { platform_auth, reset })))
        }
        _ => Err(Fmt1::Value),
    }
}

/// What [`Janus::snapshot`] wrote, with the clock readings re-based on `now`.
fn read_lifecycle(r: &mut Reader<'_>, now: u64) -> Result<Lifecycle, Fmt1> {
    let stage = r.u8()?;
    let secrets = PersistentSecrets::read(r)?;
    let owner_auth = AuthValue::read(r)?;
    let endorsement_auth = AuthValue::read(r)?;
    let lockout_auth = AuthValue::read(r)?;
    let reset_count = r.u64()?;
    let clock = r.u64()?;
    let clock_safe = bool::read(r)?;
    let saved_clock = SavedClock { clock: r.u64()?, safe: bool::read(r)? };
    let evicted = Evicted::read(r)?;
    let nv = NvStore::load(r)?;
    let orderly = match r.u8()? {
        0 => None,
        1 => Some(Orderly::Clear),
        2 => Some(Orderly::State(Box::new(Pcrs::load(r)?))),
        _ => return Err(Fmt1::Value),
    };
    let lockout = Lockout::read_live(r)?;
    let time = r.u64()?;
    let to_test = ToTest::read(r)?;
    let shut_with_state = matches!(orderly, Some(Orderly::State(_)));
    let persistent = Persistent {
        owner_auth,
        endorsement_auth,
        lockout_auth,
        secrets,
        reset_count,
        clock,
        clock_safe,
        saved_clock,
        evicted,
        nv,
        orderly,
    };
    let clocks = Clocks { last: now, time };
    Ok(match stage {
        0 => {
            let carried = read_carried(r)?;
            // A Shutdown(STATE) saves what a Resume needs; `Janus::state` relies on it.
            if shut_with_state && carried.is_none() {
                return Err(Fmt1::Value);
            }
            let stage = Initialized { carried };
            Lifecycle::Initialized(Box::new(Tpm { persistent, clocks, lockout, to_test, stage }))
        }
        1 => {
            let pcrs = Pcrs::load(r)?;
            let platform_auth = AuthValue::read(r)?;
            let reset = read_reset(r)?;
            let objects = Objects::read(r)?;
            let stage = Running { pcrs, platform_auth, reset, objects, borrowed: Cell::new(0) };
            Lifecycle::Running(Box::new(Tpm { persistent, clocks, lockout, to_test, stage }))
        }
        2 => {
            let failed = Family::from_location(r.u8()?).ok_or(Fmt1::Value)?;
            let carried = read_carried(r)?;
            if shut_with_state && carried.is_none() {
                return Err(Fmt1::Value);
            }
            let stage = Failure { failed, carried };
            Lifecycle::Failure(Box::new(Tpm { persistent, clocks, lockout, to_test, stage }))
        }
        _ => return Err(Fmt1::Value),
    })
}

/// A TPM 2.0. The device that owns it delivers each command with the locality it arrived at,
/// and calls [`Janus::init`] on a platform reset.
pub struct Janus<P: Platform> {
    platform: P,
    /// `None` only while a command is moving the TPM between stages.
    lifecycle: Option<Lifecycle>,
}

impl<P: Platform> Janus<P> {
    /// A newly manufactured TPM, as after `_TPM_Init`: new primary seeds and proofs, empty
    /// authorization values, waiting for `TPM2_Startup`.
    pub fn manufacture(mut platform: P) -> Self {
        let persistent = Persistent {
            owner_auth: AuthValue::empty(),
            endorsement_auth: AuthValue::empty(),
            lockout_auth: AuthValue::empty(),
            secrets: PersistentSecrets::generate(&mut platform),
            reset_count: 0,
            clock: 0,
            clock_safe: true,
            saved_clock: SavedClock { clock: 0, safe: true },
            evicted: Evicted::default(),
            nv: NvStore::default(),
            // A new TPM's first Startup must be a Startup(CLEAR), and it finds the state
            // orderly (`TPM_Manufacture` writes `orderlyState = TPM_SU_CLEAR`): its clock is
            // safe and no dictionary-attack failure is counted.
            orderly: Some(Orderly::Clear),
        };
        let now = platform.now_ms();
        let tpm = Tpm {
            persistent,
            clocks: Clocks { last: now, time: 0 },
            lockout: Lockout::manufactured(),
            to_test: ToTest::ALL,
            stage: Initialized { carried: None },
        };
        Janus { platform, lifecycle: Some(Lifecycle::Initialized(Box::new(tpm))) }
    }

    /// `_TPM_Init`: the platform was reset. Everything that does not survive a power cycle is
    /// gone, and the TPM waits for `TPM2_Startup` again.
    pub fn init(&mut self) {
        let now = self.platform.now_ms();
        let mut next = match self.lifecycle.take().expect("the TPM is between stages") {
            Lifecycle::Initialized(t) => t,
            Lifecycle::Running(t) => Box::new(t.stop()),
            Lifecycle::Failure(t) => {
                let Tpm { persistent, clocks, lockout, to_test, stage } = *t;
                let stage = Initialized { carried: stage.carried };
                Box::new(Tpm { persistent, clocks, lockout, to_test, stage })
            }
        };
        // The clock starts again from NV (`_TPM_Init` reads `go`).
        let saved = next.persistent.saved_clock;
        next.persistent.clock = saved.clock;
        next.persistent.clock_safe = saved.safe;
        next.clocks = Clocks { last: now, time: 0 };
        next.to_test = ToTest::ALL;
        self.lifecycle = Some(Lifecycle::Initialized(next));
    }

    /// What the TPM holds in NV: the state a power loss now would leave, for the device to store
    /// and hand to [`Janus::restore`]. It changes only when NV would be written: a command that
    /// changes persistent state, a Startup or Shutdown, a dictionary-attack failure, or `Clock`
    /// crossing a save boundary, so a caller can write it whenever it differs from the last.
    ///
    /// What a Restart or Resume needs is in it only after `TPM2_Shutdown(STATE)`, as the
    /// reference saves it only then.
    pub fn state(&self) -> Zeroizing<Vec<u8>> {
        let (persistent, lockout, carried) =
            match self.lifecycle.as_ref().expect("the TPM is between stages") {
                Lifecycle::Initialized(t) => (
                    &t.persistent,
                    &t.lockout,
                    t.stage.carried.as_deref().map(|c| (&c.platform_auth, &c.reset)),
                ),
                Lifecycle::Running(t) => {
                    (&t.persistent, &t.lockout, Some((&t.stage.platform_auth, &t.stage.reset)))
                }
                Lifecycle::Failure(t) => (
                    &t.persistent,
                    &t.lockout,
                    t.stage.carried.as_deref().map(|c| (&c.platform_auth, &c.reset)),
                ),
            };
        let mut w = Writer::new();
        persistent.secrets.write(&mut w);
        persistent.owner_auth.write(&mut w);
        persistent.endorsement_auth.write(&mut w);
        persistent.lockout_auth.write(&mut w);
        w.u64(persistent.reset_count);
        w.u64(persistent.saved_clock.clock);
        persistent.saved_clock.safe.write(&mut w);
        persistent.evicted.write(&mut w);
        persistent.nv.save(&mut w);
        lockout.write(&mut w);
        match &persistent.orderly {
            None => w.u8(0),
            Some(Orderly::Clear) => w.u8(1),
            Some(Orderly::State(pcrs)) => {
                let (platform_auth, reset) =
                    carried.expect("a TPM that shut down with STATE carries its reset state");
                w.u8(2);
                pcrs.save(&mut w);
                platform_auth.write(&mut w);
                reset.null.write(&mut w);
                reset.sessions.write(&mut w);
                w.u32(reset.clear_count);
                w.u32(reset.restart_count);
                w.u64(reset.object_sequence);
            }
        }
        state::frame(&Zeroizing::new(w.into_vec()))
    }

    /// The TPM [`Janus::state`] saved, as after `_TPM_Init`: waiting for `TPM2_Startup`.
    pub fn restore(mut platform: P, state: &[u8]) -> Result<Self, StateError> {
        let body = state::unframe(state)?;
        let invalid = |_| StateError::Invalid;
        let mut r = Reader::new(body);
        let secrets = PersistentSecrets::read(&mut r).map_err(invalid)?;
        let owner_auth = AuthValue::read(&mut r).map_err(invalid)?;
        let endorsement_auth = AuthValue::read(&mut r).map_err(invalid)?;
        let lockout_auth = AuthValue::read(&mut r).map_err(invalid)?;
        let reset_count = r.u64().map_err(invalid)?;
        let saved_clock = SavedClock {
            clock: r.u64().map_err(invalid)?,
            safe: bool::read(&mut r).map_err(invalid)?,
        };
        let evicted = Evicted::read(&mut r).map_err(invalid)?;
        let nv = NvStore::load(&mut r).map_err(invalid)?;
        let lockout = Lockout::read(&mut r).map_err(invalid)?;
        let (orderly, carried) = match r.u8().map_err(invalid)? {
            0 => (None, None),
            1 => (Some(Orderly::Clear), None),
            2 => {
                let pcrs = Pcrs::load(&mut r).map_err(invalid)?;
                let platform_auth = AuthValue::read(&mut r).map_err(invalid)?;
                let reset = ResetState {
                    null: NullSecrets::read(&mut r).map_err(invalid)?,
                    sessions: SessionTable::read(&mut r).map_err(invalid)?,
                    clear_count: r.u32().map_err(invalid)?,
                    restart_count: r.u32().map_err(invalid)?,
                    object_sequence: r.u64().map_err(invalid)?,
                };
                (
                    Some(Orderly::State(Box::new(pcrs))),
                    Some(Box::new(Carried { platform_auth, reset })),
                )
            }
            _ => return Err(StateError::Invalid),
        };
        r.finish().map_err(invalid)?;
        let persistent = Persistent {
            owner_auth,
            endorsement_auth,
            lockout_auth,
            secrets,
            reset_count,
            clock: saved_clock.clock,
            clock_safe: saved_clock.safe,
            saved_clock,
            evicted,
            nv,
            orderly,
        };
        let now = platform.now_ms();
        let tpm = Tpm {
            persistent,
            clocks: Clocks { last: now, time: 0 },
            lockout,
            to_test: ToTest::ALL,
            stage: Initialized { carried },
        };
        Ok(Janus { platform, lifecycle: Some(Lifecycle::Initialized(Box::new(tpm))) })
    }

    /// Everything the TPM holds, volatile state included: the TPM as it stands between two
    /// commands, for a VMM to keep in a snapshot of the machine and hand to [`Janus::resume`].
    /// Where [`Janus::state`] is what a power loss would leave, this is what a suspended machine
    /// resumes with: no `_TPM_Init` and no Startup come in between, as on a platform that keeps
    /// the TPM powered while it sleeps, so PCRs, loaded objects and sessions are all in it.
    pub fn snapshot(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        match self.lifecycle.as_ref().expect("the TPM is between stages") {
            Lifecycle::Initialized(t) => {
                w.u8(0);
                t.write_common(&mut w);
                write_carried(&mut w, t.stage.carried.as_deref());
            }
            Lifecycle::Running(t) => {
                debug_assert_eq!(t.stage.borrowed.get(), 0, "a command is still running");
                w.u8(1);
                t.write_common(&mut w);
                t.stage.pcrs.save(&mut w);
                t.stage.platform_auth.write(&mut w);
                write_reset(&mut w, &t.stage.reset);
                t.stage.objects.write(&mut w);
            }
            Lifecycle::Failure(t) => {
                w.u8(2);
                t.write_common(&mut w);
                w.u8(t.stage.failed.location() as u8);
                write_carried(&mut w, t.stage.carried.as_deref());
            }
        }
        state::frame_snapshot(&Zeroizing::new(w.into_vec()))
    }

    /// The TPM [`Janus::snapshot`] took, as it stood: the same stage, PCRs, objects and
    /// sessions, with `Clock` and `Time` going on from where they were however `platform`'s
    /// clock reads now.
    pub fn resume(mut platform: P, snapshot: &[u8]) -> Result<Self, StateError> {
        let body = state::unframe_snapshot(snapshot)?;
        let mut r = Reader::new(body);
        let now = platform.now_ms();
        let lifecycle = read_lifecycle(&mut r, now).map_err(|_| StateError::Invalid)?;
        r.finish().map_err(|_| StateError::Invalid)?;
        Ok(Janus { platform, lifecycle: Some(lifecycle) })
    }

    /// Executes one command and returns its response. Nothing a guest sends can make this
    /// panic: every fault in the command is a response code.
    pub fn execute(&mut self, locality: Locality, bytes: &[u8]) -> Vec<u8> {
        match self.dispatch(locality, bytes) {
            Ok(r) => r,
            Err(rc) => command::error(rc),
        }
    }

    fn dispatch(&mut self, locality: Locality, bytes: &[u8]) -> Result<Vec<u8>, Rc> {
        // In failure mode not even the frame is checked as usual: the reference answers
        // before it parses anything (`TpmFailureMode`).
        if let Some(Lifecycle::Failure(t)) = &self.lifecycle {
            return Ok(selftest::failure_answer(t.stage.failed, bytes));
        }
        let cmd = command::frame(bytes)?;
        let now = self.platform.now_ms();
        let mut lifecycle = self.lifecycle.take().expect("the TPM is between stages");
        match &mut lifecycle {
            Lifecycle::Initialized(t) => t.tick(now),
            Lifecycle::Running(t) => {
                t.tick(now);
                t.lockout.self_heal(t.time());
            }
            Lifecycle::Failure(_) => unreachable!("failure mode answered above"),
        }
        // Each family a command may use is tested before the command reads anything, so a
        // failure leaves the state as it was (the reference commits nothing from a command
        // that entered failure mode).
        let families = selftest::families(cmd.cc);
        let failed = match &mut lifecycle {
            Lifecycle::Initialized(t) if cmd.cc == Cc::Startup => {
                t.to_test.test(families, &mut self.platform);
                t.to_test.failed()
            }
            Lifecycle::Running(t) if cmd.cc != Cc::Startup => {
                t.to_test.test(families, &mut self.platform);
                t.to_test.failed()
            }
            _ => None,
        };
        if let Some(failed) = failed {
            self.lifecycle = Some(lifecycle.fail(failed));
            return Err(Fmt0::Failure.into());
        }
        let (next, result) = match lifecycle {
            Lifecycle::Failure(_) => unreachable!("failure mode answered above"),
            Lifecycle::Initialized(tpm) if cmd.cc == Cc::Startup => {
                match (*tpm).startup(&mut self.platform, locality, cmd) {
                    Ok((running, response)) => {
                        (Lifecycle::Running(Box::new(running)), Ok(response))
                    }
                    Err(refused) => {
                        let (tpm, rc) = *refused;
                        (Lifecycle::Initialized(Box::new(tpm)), Err(rc))
                    }
                }
            }
            Lifecycle::Initialized(tpm) => {
                (Lifecycle::Initialized(tpm), Err(Fmt0::Initialize.into()))
            }
            Lifecycle::Running(tpm) if cmd.cc == Cc::Startup => {
                (Lifecycle::Running(tpm), Err(Fmt0::Initialize.into()))
            }
            Lifecycle::Running(mut tpm) => {
                let r = tpm.execute(&mut self.platform, locality, cmd);
                // Only TPM2_SelfTest tests here; what it found wrong is the response.
                match tpm.to_test.failed() {
                    Some(failed) => {
                        (Lifecycle::Running(tpm).fail(failed), Err(Fmt0::Failure.into()))
                    }
                    None => (Lifecycle::Running(tpm), r),
                }
            }
        };
        self.lifecycle = Some(next);
        result
    }
}

impl Lifecycle {
    /// Failure mode, keeping what a Restart or Resume after the next `_TPM_Init` needs.
    fn fail(self, failed: Family) -> Lifecycle {
        let t = match self {
            Lifecycle::Initialized(t) => *t,
            Lifecycle::Running(t) => t.stop(),
            Lifecycle::Failure(t) => return Lifecycle::Failure(t),
        };
        let Tpm { persistent, clocks, lockout, to_test, stage } = t;
        let stage = Failure { failed, carried: stage.carried };
        Lifecycle::Failure(Box::new(Tpm { persistent, clocks, lockout, to_test, stage }))
    }
}

/// `TPM_SU`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StartupType {
    Clear,
    State,
}

impl StartupType {
    fn read(r: &mut Reader<'_>) -> Result<StartupType, Fmt1> {
        match r.u16()? {
            0 => Ok(StartupType::Clear),
            1 => Ok(StartupType::State),
            _ => Err(Fmt1::Value),
        }
    }
}

/// A Startup that failed: the TPM, still waiting for one, and why.
type Refused = (Tpm<Initialized>, Rc);

impl Tpm<Initialized> {
    fn startup(
        mut self,
        platform: &mut impl Platform,
        locality: Locality,
        mut cmd: Command<'_>,
    ) -> Result<(Tpm<Running>, Vec<u8>), Box<Refused>> {
        let tag = cmd.tag;
        let parsed = (|| {
            let auth = Authorization::read(
                cmd.area(),
                &SessionTable::default(),
                Cc::Startup.code(),
                Cc::Startup.attributes(),
                Vec::new(),
            )?;
            let mut r = Reader::new(cmd.params());
            let kind = StartupType::read(&mut r).at(At::param(1))?;
            r.finish().map_err(Rc::bare)?;
            Ok((auth, kind))
        })();
        let kind = match parsed {
            Ok((_, kind)) => kind,
            Err(rc) => return Err(Box::new((self, rc))),
        };
        // The PC Client platform starts the TPM from locality 0 or 3 only.
        if locality.get() != 0 && locality.get() != 3 {
            return Err(Box::new((self, Warn::Locality.into())));
        }
        // Refused before anything is taken, so a refused Startup(STATE) leaves the orderly state
        // for the next Startup (`TPM2_Startup` returns before it writes `orderlyState`).
        let resumable = matches!(self.persistent.orderly, Some(Orderly::State(_)))
            && self.stage.carried.is_some();
        if kind == StartupType::State && !resumable {
            return Err(Box::new((self, Rc::Fmt1(Fmt1::Value, Some(At::param(1))))));
        }
        let orderly = self.persistent.orderly.take();
        let was_orderly = orderly.is_some();
        let carried = self.stage.carried.take();
        let (pcrs, platform_auth, reset) = match (kind, orderly, carried) {
            (StartupType::State, Some(Orderly::State(saved)), Some(c)) => {
                let mut reset = c.reset;
                reset.restart_count = reset.restart_count.wrapping_add(1);
                (Pcrs::resume(&saved, locality), c.platform_auth, reset)
            }
            (StartupType::State, _, _) => unreachable!("a Startup(STATE) with nothing to resume"),
            (StartupType::Clear, Some(Orderly::State(saved)), Some(c)) => {
                let mut reset = c.reset;
                reset.clear_count = reset.clear_count.wrapping_add(1);
                reset.restart_count = reset.restart_count.wrapping_add(1);
                self.persistent.nv.startup(false);
                (Pcrs::restart(&saved, locality), AuthValue::empty(), reset)
            }
            (StartupType::Clear, _, _) => {
                // A restored state may hold any count; the reference's counter wraps.
                self.persistent.reset_count = self.persistent.reset_count.wrapping_add(1);
                self.persistent.nv.startup(true);
                (Pcrs::reset(locality), AuthValue::empty(), ResetState::new(platform))
            }
        };
        if !was_orderly {
            self.persistent.clock_safe = false;
        }
        self.lockout.startup(was_orderly);
        let time = self.time();
        self.lockout.self_heal(time);
        let running = Tpm {
            persistent: self.persistent,
            clocks: self.clocks,
            lockout: self.lockout,
            to_test: self.to_test,
            stage: Running {
                pcrs,
                platform_auth,
                reset,
                objects: Objects::default(),
                borrowed: Cell::new(0),
            },
        };
        Ok((running, command::success(tag, None, &[], &[])))
    }
}

impl Entity for PcrOrNull {}
impl Entity for HierarchyAuth {}
impl Entity for Hierarchy {}
impl Entity for Loaded {}
impl Entity for SequenceSlot {}
impl Entity for NvRef {}

/// A handle's name for the cpHash: an object's is its name, everything else's is its handle.
/// `TPMI_RH_PROVISION`: the owner or the platform, else `TPM_RC_VALUE` on the first handle.
fn provision_handle(h: u32) -> Result<HierarchyAuth, Rc> {
    match h {
        crate::handle::rh::OWNER => Ok(HierarchyAuth::Owner),
        crate::handle::rh::PLATFORM => Ok(HierarchyAuth::Platform),
        _ => Err(Rc::Fmt1(Fmt1::Value, Some(At::handle(1)))),
    }
}

/// `TPMI_RH_NV_INDEX` as handle `n`: `TPM_RC_VALUE` for any other handle type.
fn nv_index_handle(h: u32, n: u8) -> Result<u32, Rc> {
    if handle_type(h) == ht::NV_INDEX {
        Ok(h)
    } else {
        Err(Rc::Fmt1(Fmt1::Value, Some(At::handle(n))))
    }
}

fn handle_name(h: u32) -> Name2b {
    Buf::from_array(h.to_be_bytes())
}

/// The authorization value of a hierarchy, by the role `TPM2_HierarchyChangeAuth` and the
/// permanent handles give them.
fn hierarchy_value<'a>(
    p: &'a Persistent,
    platform_auth: &'a AuthValue,
    h: HierarchyAuth,
) -> &'a AuthValue {
    match h {
        HierarchyAuth::Owner => &p.owner_auth,
        HierarchyAuth::Endorsement => &p.endorsement_auth,
        HierarchyAuth::Lockout => &p.lockout_auth,
        HierarchyAuth::Platform => platform_auth,
    }
}

/// `TPMI_RH_LOCKOUT`: `TPM_RH_LOCKOUT` and nothing else (VALUE on the first handle).
fn lockout_handle(h: u32) -> Result<HierarchyAuth, Rc> {
    match HierarchyAuth::from_handle(h) {
        Some(HierarchyAuth::Lockout) => Ok(HierarchyAuth::Lockout),
        _ => Err(Rc::Fmt1(Fmt1::Value, Some(At::handle(1)))),
    }
}

fn hierarchy_da(h: HierarchyAuth) -> Da {
    if h == HierarchyAuth::Lockout { Da::Lockout } else { Da::Exempt }
}

/// The empty authorization value of a PCR or of `TPM_RH_NULL`.
static EMPTY: AuthValue = AuthValue::empty();

/// A hierarchy as `TPMI_RH_HIERARCHY` names it, with its authorization role.
fn hierarchy_role(h: Hierarchy) -> Option<HierarchyAuth> {
    match h {
        Hierarchy::Owner => Some(HierarchyAuth::Owner),
        Hierarchy::Endorsement => Some(HierarchyAuth::Endorsement),
        Hierarchy::Platform => Some(HierarchyAuth::Platform),
        Hierarchy::Null => None,
    }
}

/// The parsed parameters of `TPM2_StartAuthSession`.
struct StartAuthSessionIn {
    nonce_caller: Buf<MAX_DIGEST>,
    encrypted_salt: Buf<MAX_ENCRYPTED_SECRET>,
    session_type: SessionType,
    symmetric: SymDef,
    auth_hash: Hash,
}

/// `TPM2B_ENCRYPTED_SECRET`: at most an RSA-2048 ciphertext.
const MAX_ENCRYPTED_SECRET: usize = 256;

/// `TPM_ST_CREATION`.
const ST_CREATION: u16 = 0x8021;
/// The OAEP label of a salt encrypted to an RSA key (`SECRET_KEY`), its NUL included.
const SECRET_LABEL: &[u8] = b"SECRET\0";
/// `TPM_GENERATED_VALUE`, which starts every structure the TPM signs.
const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
/// `TPM_ALG_NULL`, a primary object's parent nameAlg.
const NULL_ALG: u16 = crate::alg::id::NULL;
/// `MAX_DIGEST_BUFFER`.
const MAX_BUFFER: usize = 1024;

/// What a new object's creation data is made from, beside the object and its parent.
struct Creation {
    outside: Data2b,
    pcrs: List<Selection, 1>,
    locality: Locality,
}

/// `TPMT_TK_HASHCHECK`.
struct HashCheck {
    hierarchy: u32,
    digest: Vec<u8>,
}

impl Marshal for HashCheck {
    fn write(&self, w: &mut Writer) {
        w.u16(ST_HASHCHECK);
        w.u32(self.hierarchy);
        w.tpm2b(&self.digest);
    }
}

impl Tpm<Running> {
    /// What survives a platform reset: loaded sessions and objects and the PCRs are gone, and
    /// the rest is carried for a Restart or Resume.
    fn stop(self) -> Tpm<Initialized> {
        let Tpm { persistent, clocks, lockout, to_test, stage } = self;
        let Running { platform_auth, mut reset, .. } = stage;
        reset.sessions.drop_loaded();
        let carried = Some(Box::new(Carried { platform_auth, reset }));
        Tpm { persistent, clocks, lockout, to_test, stage: Initialized { carried } }
    }

    fn execute(
        &mut self,
        platform: &mut impl Platform,
        locality: Locality,
        mut cmd: Command<'_>,
    ) -> Result<Vec<u8>, Rc> {
        let tag = cmd.tag;
        let cc = cmd.cc;
        let attributes = cc.attributes();
        self.stage.borrowed.set(0);
        // Each arm classifies the handles (TPM_RC_VALUE at the handle), checks that what they
        // name is loaded (TPM_RC_REFERENCE_Hn / TPM_RC_HANDLE), then reads the authorization
        // area, authorizes the handles that need it, and reads the parameters; the reference's
        // order. It returns the response handle, the parameters and the authorization that
        // answers for the command.
        let (handle, out, auth): (Option<u32>, Writer, Authorization) = match cc {
            Cc::Startup => unreachable!("Startup is dispatched to an initialized TPM"),
            Cc::Shutdown => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let kind = StartupType::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.persistent.orderly = Some(match kind {
                    StartupType::State => Orderly::State(Box::new(self.stage.pcrs.clone())),
                    StartupType::Clear => Orderly::Clear,
                });
                self.persistent.saved_clock =
                    SavedClock { clock: self.persistent.clock, safe: self.persistent.clock_safe };
                (None, Writer::new(), auth)
            }
            Cc::SelfTest => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let full = bool::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.to_test.self_test(full, platform);
                (None, Writer::new(), auth)
            }
            Cc::GetTestResult => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                // Running, every test so far has passed: no data, and TPM_RC_SUCCESS
                // (`TPM2_GetTestResult` via `CryptGetTestResult`).
                let mut out = Writer::new();
                out.tpm2b(&[]);
                out.u32(0);
                (None, out, auth)
            }
            Cc::GetCapability => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let capability = r.u32().at(At::param(1))?;
                let property = r.u32().at(At::param(2))?;
                let count = r.u32().at(At::param(3))?;
                r.finish().map_err(Rc::bare)?;
                let mut out = Writer::new();
                capability::get(capability, property, count, &self.variable(), &mut out)?;
                (None, out, auth)
            }
            Cc::GetRandom => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let requested = r.u16().at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let mut bytes = vec![0u8; usize::from(requested).min(MAX_DIGEST)];
                platform.fill_random(&mut bytes);
                let mut out = Writer::new();
                out.tpm2b(&bytes);
                (None, out, auth)
            }
            Cc::ReadClock => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                // TPMS_TIME_INFO: time, then TPMS_CLOCK_INFO.
                let mut out = Writer::new();
                out.u64(self.time());
                out.u64(self.persistent.clock);
                out.u32(self.persistent.reset_count as u32);
                out.u32(self.stage.reset.restart_count);
                out.u8(u8::from(self.persistent.clock_safe));
                (None, out, auth)
            }
            Cc::PcrRead => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let selection = pcr::read_selection_list(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let (counter, selection, digests) = self.stage.pcrs.read(selection);
                let mut out = Writer::new();
                out.u32(counter);
                pcr::write_selection_list(&mut out, &selection);
                out.u32(digests.len() as u32);
                for d in &digests {
                    out.tpm2b(d.as_slice());
                }
                (None, out, auth)
            }
            Cc::PcrExtend => {
                let [h] = cmd.handles()?;
                let target = PcrOrNull::from_handle(h).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let entity = EntityAuth {
                    name: &h.to_be_bytes(),
                    value: &EMPTY,
                    policy: &[],
                    da: Da::Exempt,
                    value_available: true,
                };
                let target = auth.authorize(
                    &self.stage.reset.sessions,
                    raw,
                    target,
                    &entity,
                    &mut self.lockout,
                    self.stage.pcrs.counter(),
                )?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let digests = read_digest_values(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.pcr_extend(target, locality, &digests)?;
                (None, Writer::new(), auth)
            }
            Cc::EvictControl => {
                let [a, h] = cmd.handles()?;
                let provision = provision_handle(a)?;
                let target = self.object_handle(h, false, 2)?.expect("not NULL");
                let names = vec![handle_name(a), self.name_of_object(Some(target))];
                let mut auth = self.read_auth(&mut cmd, names)?;
                let raw = cmd.params();
                let provision = self.authorize_hierarchy(&mut auth, raw, provision)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                // TPMI_DH_PERSISTENT.
                let persistent = r.u32().at(At::param(1))?;
                if handle_type(persistent) != ht::PERSISTENT {
                    return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1))));
                }
                r.finish().map_err(Rc::bare)?;
                self.evict_control(provision.entity(), target, persistent)?;
                (None, Writer::new(), auth)
            }
            Cc::NvDefineSpace => {
                let [a] = cmd.handles()?;
                let provision = provision_handle(a)?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(a)])?;
                let raw = cmd.params();
                self.authorize_hierarchy(&mut auth, raw, provision)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let value = r.tpm2b::<MAX_DIGEST>().at(At::param(1))?;
                let public = Tpm2b::<NvPublic>::read(&mut r).at(At::param(2))?.0;
                r.finish().map_err(Rc::bare)?;
                let platform = provision == HierarchyAuth::Platform;
                self.persistent.nv.define(platform, value.get(), public)?;
                (None, Writer::new(), auth)
            }
            Cc::NvUndefineSpace => {
                let [a, h] = cmd.handles()?;
                let provision = provision_handle(a)?;
                let index = nv_index_handle(h, 2)?;
                let index = self.nv_find(index, 2)?;
                let names = vec![handle_name(a), self.nv_name(index)];
                let mut auth = self.read_auth(&mut cmd, names)?;
                let raw = cmd.params();
                self.authorize_hierarchy(&mut auth, raw, provision)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                self.persistent.nv.undefine(provision == HierarchyAuth::Platform, index)?;
                (None, Writer::new(), auth)
            }
            Cc::NvWrite | Cc::NvExtend | Cc::NvRead => {
                let [a, h] = cmd.handles()?;
                // TPMI_RH_NV_AUTH, then TPMI_RH_NV_INDEX; then whether each is defined.
                let by = match a {
                    crate::handle::rh::OWNER => NvAuth::Owner,
                    crate::handle::rh::PLATFORM => NvAuth::Platform,
                    _ if a == h => NvAuth::Index,
                    _ => NvAuth::OtherIndex,
                };
                let authorizer = match by {
                    NvAuth::Owner | NvAuth::Platform => None,
                    NvAuth::Index | NvAuth::OtherIndex => Some(nv_index_handle(a, 1)?),
                };
                let index = nv_index_handle(h, 2)?;
                let authorizer = match authorizer {
                    Some(i) => Some(self.nv_find(i, 1)?),
                    None => None,
                };
                let index = self.nv_find(index, 2)?;
                let names = vec![
                    authorizer.map_or_else(|| handle_name(a), |i| self.nv_name(i)),
                    self.nv_name(index),
                ];
                let mut auth = self.read_auth(&mut cmd, names)?;
                let raw = cmd.params();
                let write = cc != Cc::NvRead;
                match authorizer {
                    Some(i) => {
                        self.authorize_nv(&mut auth, raw, i, write)?;
                    }
                    None => {
                        let h = if by == NvAuth::Owner {
                            HierarchyAuth::Owner
                        } else {
                            HierarchyAuth::Platform
                        };
                        self.authorize_hierarchy(&mut auth, raw, h)?;
                    }
                }
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let mut out = Writer::new();
                let orderly = match cc {
                    Cc::NvRead => {
                        let size = r.u16().at(At::param(1))?;
                        let offset = r.u16().at(At::param(2))?;
                        r.finish().map_err(Rc::bare)?;
                        out.tpm2b(self.persistent.nv.read(by, index, size, offset)?);
                        false
                    }
                    Cc::NvWrite => {
                        let data = r.tpm2b::<{ nv::MAX_NV_BUFFER_SIZE }>().at(At::param(1))?;
                        let offset = r.u16().at(At::param(2))?;
                        r.finish().map_err(Rc::bare)?;
                        self.persistent.nv.write(by, index, data.get(), offset)?
                    }
                    _ => {
                        let data = r.tpm2b::<{ nv::MAX_NV_BUFFER_SIZE }>().at(At::param(1))?;
                        r.finish().map_err(Rc::bare)?;
                        self.persistent.nv.extend(by, index, data.get())?
                    }
                };
                // A write to an index kept in RAM makes the last orderly shutdown's saved state
                // stale (`g_clearOrderly`).
                if orderly {
                    self.persistent.orderly = None;
                }
                (None, out, auth)
            }
            Cc::NvReadPublic => {
                let [h] = cmd.handles()?;
                let index = nv_index_handle(h, 1)?;
                let index = self.nv_find(index, 1)?;
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let public = &self.persistent.nv.get(index).public;
                let mut out = Writer::new();
                Tpm2b(public.clone()).write(&mut out);
                public.name().write(&mut out);
                (None, out, auth)
            }
            Cc::HierarchyChangeAuth => {
                let [h] = cmd.handles()?;
                let hierarchy =
                    HierarchyAuth::from_handle(h).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let hierarchy = self.authorize_hierarchy(&mut auth, raw, hierarchy)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let new = AuthValue::from_wire(r.tpm2b::<MAX_DIGEST>().at(At::param(1))?);
                r.finish().map_err(Rc::bare)?;
                // The response is computed with the new value (EntityGetAuthValue runs after
                // the command).
                auth.set_response_auth(0, &new);
                self.hierarchy_change_auth(hierarchy, new);
                (None, Writer::new(), auth)
            }
            // TPM2_DictionaryAttackLockReset: the lockout hierarchy clears the failure count.
            Cc::DictionaryAttackLockReset => {
                let [h] = cmd.handles()?;
                let lockout = lockout_handle(h)?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                self.authorize_hierarchy(&mut auth, raw, lockout)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                self.lockout.reset();
                (None, Writer::new(), auth)
            }
            // TPM2_DictionaryAttackParameters: the lockout hierarchy sets the limit and the two
            // recovery times. The failure count is left as it is.
            Cc::DictionaryAttackParameters => {
                let [h] = cmd.handles()?;
                let lockout = lockout_handle(h)?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                self.authorize_hierarchy(&mut auth, raw, lockout)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let max_tries = r.u32().at(At::param(1))?;
                let recovery_time = r.u32().at(At::param(2))?;
                let lockout_recovery = r.u32().at(At::param(3))?;
                r.finish().map_err(Rc::bare)?;
                self.lockout.set_parameters(max_tries, recovery_time, lockout_recovery);
                (None, Writer::new(), auth)
            }
            Cc::CreatePrimary => {
                let [h] = cmd.handles()?;
                let hierarchy =
                    Hierarchy::from_handle(h, true).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let role = hierarchy_role(hierarchy);
                let entity = EntityAuth {
                    name: &h.to_be_bytes(),
                    value: match role {
                        Some(r) => hierarchy_value(&self.persistent, &self.stage.platform_auth, r),
                        None => &EMPTY,
                    },
                    policy: &[],
                    da: Da::Exempt,
                    value_available: true,
                };
                let hierarchy = auth.authorize(
                    &self.stage.reset.sessions,
                    raw,
                    hierarchy,
                    &entity,
                    &mut self.lockout,
                    self.stage.pcrs.counter(),
                )?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let sensitive = Tpm2b::<SensitiveCreate>::read(&mut r).at(At::param(1))?.0;
                let template = Tpm2b::<crate::types::Public>::read(&mut r).at(At::param(2))?.0;
                let outside = Data2b::read(&mut r).at(At::param(3))?;
                let creation_pcr = List::<Selection, 1>::read(&mut r).at(At::param(4))?;
                r.finish().map_err(Rc::bare)?;
                let (handle, out) = self.create_primary(
                    hierarchy,
                    sensitive,
                    template,
                    outside,
                    creation_pcr,
                    locality,
                )?;
                (Some(handle), out, auth)
            }
            Cc::ReadPublic => {
                let [h] = cmd.handles()?;
                let target = self.object_handle(h, false, 1)?;
                let mut auth = self.read_auth(&mut cmd, vec![self.name_of_object(target)])?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let o = self.object(target.expect("ReadPublic refuses NULL"));
                let mut out = Writer::new();
                Tpm2b(&o.public).write(&mut out);
                o.name().write(&mut out);
                o.qualified_name.write(&mut out);
                (None, out, auth)
            }
            Cc::StartAuthSession => {
                let [k, b] = cmd.handles()?;
                let tpm_key =
                    ObjectHandle::from_handle(k, true).ok_or(Fmt1::Value).at(At::handle(1))?;
                let bind =
                    EntityHandle::from_handle(b, true).ok_or(Fmt1::Value).at(At::handle(2))?;
                let tpm_key = self.resolve_object(tpm_key, 1)?;
                let bind_loaded = self.resolve_entity(bind, 2)?;
                let names = vec![self.name_of_object(tpm_key), self.entity_name(bind, bind_loaded)];
                let mut auth = self.read_auth(&mut cmd, names)?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let input = StartAuthSessionIn {
                    nonce_caller: Buf::read(&mut r).at(At::param(1))?,
                    encrypted_salt: Buf::read(&mut r).at(At::param(2))?,
                    session_type: SessionType::read(&mut r).at(At::param(3))?,
                    symmetric: SymDef::read(&mut r).at(At::param(4))?,
                    auth_hash: Hash::read(&mut r).at(At::param(5))?,
                };
                r.finish().map_err(Rc::bare)?;
                let (handle, out) =
                    self.start_auth_session(platform, tpm_key, bind, bind_loaded, input)?;
                (Some(handle), out, auth)
            }
            Cc::ContextSave => {
                let [h] = cmd.handles()?;
                let target = ContextHandle::from_handle(h).ok_or(Fmt1::Value).at(At::handle(1))?;
                let target = self.resolve_context(target)?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let out = self.context_save(target, h)?;
                (None, out, auth)
            }
            Cc::ContextLoad => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let context = Context::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let handle = self.context_load(context)?;
                (Some(handle), Writer::new(), auth)
            }
            Cc::FlushContext => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let h = r.u32().at(At::param(1))?;
                let target = ContextHandle::from_handle(h).ok_or(Fmt1::Value).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.flush_context(target)?;
                (None, Writer::new(), auth)
            }
            Cc::Create => {
                let [h] = cmd.handles()?;
                let parent = self.object_handle(h, false, 1)?.expect("a TPMI_DH_OBJECT");
                let mut auth = self.read_auth(&mut cmd, vec![self.name_of_object(Some(parent))])?;
                let raw = cmd.params();
                let parent = self.authorize_object(&mut auth, raw, parent)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let sensitive = Tpm2b::<SensitiveCreate>::read(&mut r).at(At::param(1))?.0;
                let template = Tpm2b::<crate::types::Public>::read(&mut r).at(At::param(2))?.0;
                let outside = Data2b::read(&mut r).at(At::param(3))?;
                let creation_pcr = List::<Selection, 1>::read(&mut r).at(At::param(4))?;
                r.finish().map_err(Rc::bare)?;
                let out = self.create(
                    platform,
                    parent,
                    sensitive,
                    template,
                    Creation { outside, pcrs: creation_pcr, locality },
                )?;
                (None, out, auth)
            }
            Cc::Load => {
                let [h] = cmd.handles()?;
                let parent = self.object_handle(h, false, 1)?.expect("a TPMI_DH_OBJECT");
                let mut auth = self.read_auth(&mut cmd, vec![self.name_of_object(Some(parent))])?;
                let raw = cmd.params();
                let parent = self.authorize_object(&mut auth, raw, parent)?;
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let private = object::Private::read(&mut r).at(At::param(1))?;
                let public = Tpm2b::<crate::types::Public>::read(&mut r).at(At::param(2))?.0;
                r.finish().map_err(Rc::bare)?;
                let (handle, out) = self.load(parent, private, public)?;
                (Some(handle), out, auth)
            }
            Cc::Unseal => {
                let [h] = cmd.handles()?;
                let item = self.object_handle(h, false, 1)?.expect("a TPMI_DH_OBJECT");
                let mut auth = self.read_auth(&mut cmd, vec![self.name_of_object(Some(item))])?;
                let raw = cmd.params();
                let item = self.authorize_object(&mut auth, raw, item)?.entity();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let o = self.object(item);
                let SensitiveKind::KeyedHash(data) = &o.sensitive.kind else {
                    return Err(Rc::Fmt1(Fmt1::Type, Some(At::handle(1))));
                };
                let a = o.public.attributes;
                if a.decrypt() || a.sign_encrypt() || a.restricted() {
                    return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(1))));
                }
                let mut out = Writer::new();
                out.tpm2b(data.as_slice());
                (None, out, auth)
            }
            Cc::PolicyPcr
            | Cc::PolicyAuthValue
            | Cc::PolicyPassword
            | Cc::PolicyCommandCode
            | Cc::PolicyRestart
            | Cc::PolicyGetDigest => {
                let [h] = cmd.handles()?;
                let session = self.policy_session(h)?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let out = self.policy(cc, session, &params)?;
                (None, out, auth)
            }
            Cc::Hash => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let data = Buf::<MAX_BUFFER>::read(&mut r).at(At::param(1))?;
                let hash = Hash::read(&mut r).at(At::param(2))?;
                let h = r.u32().at(At::param(3))?;
                let hierarchy =
                    Hierarchy::from_handle(h, true).ok_or(Fmt1::Value).at(At::param(3))?;
                r.finish().map_err(Rc::bare)?;
                let digest = hash.digest(&[data.as_slice()]);
                let mut out = Writer::new();
                out.tpm2b(digest.as_slice());
                self.hash_check(hierarchy, hash, digest.as_slice(), data.as_slice())
                    .write(&mut out);
                (None, out, auth)
            }
            Cc::TestParms => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                // Everything TPM2_TestParms checks, unmarshalling checks.
                crate::types::PublicParms::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                (None, Writer::new(), auth)
            }
            Cc::EccParameters => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let curve = crate::types::EccCurve::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let mut out = Writer::new();
                crypto::ecc_parameters(curve, &mut out);
                (None, out, auth)
            }
            Cc::Sign | Cc::RsaDecrypt => {
                let [h] = cmd.handles()?;
                let key = self.object_handle(h, false, 1)?.expect("a TPMI_DH_OBJECT");
                let mut auth = self.read_auth(&mut cmd, vec![self.name_of_object(Some(key))])?;
                let raw = cmd.params();
                let key = self.authorize_object(&mut auth, raw, key)?.entity();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let out = if cc == Cc::Sign {
                    let digest = Digest2b::read(&mut r).at(At::param(1))?;
                    let scheme = SigScheme::read(&mut r).at(At::param(2))?;
                    let ticket = HashCheckTicket::read(&mut r).at(At::param(3))?;
                    r.finish().map_err(Rc::bare)?;
                    self.sign(platform, key, digest.as_slice(), scheme, ticket)?
                } else {
                    let c = Buf::<{ crypto::RSA_MODULUS_BYTES }>::read(&mut r).at(At::param(1))?;
                    let scheme = RsaDecryptScheme::read(&mut r).at(At::param(2))?;
                    let label = Data2b::read(&mut r).at(At::param(3))?;
                    r.finish().map_err(Rc::bare)?;
                    self.rsa_decrypt(platform, key, c.as_slice(), scheme, label.as_slice())?
                };
                (None, out, auth)
            }
            Cc::HashSequenceStart => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let value = crate::types::Secret::<MAX_DIGEST>::read(&mut r).at(At::param(1))?;
                // TPMI_ALG_HASH+: NULL starts an event sequence.
                let alg = r.u16().at(At::param(2))?;
                let event = alg == crate::alg::id::NULL;
                if !event {
                    Hash::from_id(alg).ok_or(Fmt1::Hash).at(At::param(2))?;
                }
                r.finish().map_err(Rc::bare)?;
                let q = HashSequence::new(value, event);
                let s = self.stage.objects.insert_sequence(q).ok_or(Warn::ObjectMemory)?;
                (Some(s.handle()), Writer::new(), auth)
            }
            Cc::SequenceUpdate | Cc::SequenceComplete => {
                let [h] = cmd.handles()?;
                let target = self.sequence_handle(h)?;
                let name = match target {
                    Ok(_) => Buf::empty(),
                    Err(l) => self.name_of_object(Some(l)),
                };
                let mut auth = self.read_auth(&mut cmd, vec![name])?;
                let raw = cmd.params();
                let target = match target {
                    Ok(q) => Ok(self.authorize_sequence(&mut auth, raw, q)?.entity()),
                    Err(l) => Err(self.authorize_object(&mut auth, raw, l)?.entity()),
                };
                let params = auth.finish(&self.stage.reset.sessions, raw, &mut self.lockout)?;
                let mut r = Reader::new(&params);
                let data = Buf::<MAX_BUFFER>::read(&mut r).at(At::param(1))?;
                let hierarchy = if cc == Cc::SequenceComplete {
                    Some(Hierarchy::read(&mut r).at(At::param(2))?)
                } else {
                    None
                };
                r.finish().map_err(Rc::bare)?;
                // A key where a sequence belongs: TPM_RC_MODE on the handle.
                let q = target.map_err(|_| Rc::Fmt1(Fmt1::Mode, Some(At::handle(1))))?;
                let out = match hierarchy {
                    None => {
                        self.stage.objects.sequence_mut(q).update(data.as_slice());
                        Writer::new()
                    }
                    Some(hierarchy) => self.sequence_complete(q, data.as_slice(), hierarchy)?,
                };
                (None, out, auth)
            }
        };
        debug_assert_eq!(handle.is_some(), attributes.response_handle, "{cc:?}");
        let (params, area) = auth.respond(&mut self.stage.reset.sessions, platform, out.into_vec());
        Ok(command::success(tag, handle, &params, &area))
    }

    fn read_auth(&self, cmd: &mut Command<'_>, names: Vec<Name2b>) -> Result<Authorization, Rc> {
        let cc = cmd.cc;
        Authorization::read(
            cmd.area(),
            &self.stage.reset.sessions,
            cc.code(),
            cc.attributes(),
            names,
        )
    }

    fn variable(&self) -> Variable {
        let p = &self.persistent;
        let sessions = &self.stage.reset.sessions;
        Variable {
            owner_auth_set: !p.owner_auth.is_empty(),
            endorsement_auth_set: !p.endorsement_auth.is_empty(),
            lockout_auth_set: !p.lockout_auth.is_empty(),
            in_lockout: self.lockout.in_lockout(),
            lockout: self.lockout.properties(),
            orderly: p.orderly.is_some(),
            transient: self.stage.objects.handles_from(0),
            persistent: self.persistent.evicted.handles_from(0),
            nv: self.persistent.nv.handles_from(0),
            loaded_sessions: sessions.handles_from(0, false),
            saved_sessions: sessions.handles_from(0, true),
        }
    }

    fn secrets(&self) -> Secrets<'_> {
        Secrets { persistent: &self.persistent.secrets, null: &self.stage.reset.null }
    }

    fn epoch(&self) -> Epoch {
        Epoch {
            reset_count: self.persistent.reset_count,
            clear_count: self.stage.reset.clear_count,
        }
    }

    /// A `TPMI_DH_OBJECT` handle that must name a loaded object: `TPM_RC_VALUE` at the handle
    /// for another type, `TPM_RC_REFERENCE_Hn` for an empty slot, `TPM_RC_HANDLE` for a
    /// persistent handle (none can exist yet).
    fn object_handle(&self, h: u32, allow_null: bool, n: u8) -> Result<Option<Loaded>, Rc> {
        let o = ObjectHandle::from_handle(h, allow_null).ok_or(Fmt1::Value).at(At::handle(n))?;
        self.resolve_object(o, n)
    }

    fn resolve_object(&self, o: ObjectHandle, n: u8) -> Result<Option<Loaded>, Rc> {
        let slot = Slot::new(n - 1).expect("at most seven handles");
        match o {
            ObjectHandle::Null => Ok(None),
            ObjectHandle::Transient(h) => match self.stage.objects.find(h) {
                Some(l) => Ok(Some(l)),
                // A running hash sequence where a key belongs. The reference lets each command
                // find this out for itself after authorization, with its own code
                // (TPM_RC_SEQUENCE from ReadPublic, KEY or TYPE from most others); janus
                // answers TPM_RC_SEQUENCE for all of them, before authorization.
                None if self.stage.objects.find_sequence(h).is_some() => Err(Fmt0::Sequence.into()),
                None => Err(Warn::ReferenceH(slot).into()),
            },
            ObjectHandle::Persistent(h) => {
                // The reference copies the object into a free slot first (`ObjectLoadEvict`):
                // TPM_RC_OBJECT_MEMORY before TPM_RC_HANDLE.
                if self.slots_full() {
                    return Err(Warn::ObjectMemory.into());
                }
                let l = self
                    .persistent
                    .evicted
                    .find(h)
                    .ok_or(Rc::Fmt1(Fmt1::Handle, Some(At::handle(n))))?;
                self.stage.borrowed.set(self.stage.borrowed.get() + 1);
                Ok(Some(l))
            }
        }
    }

    /// The defined index `h` names: `TPM_RC_HANDLE` on handle `n` when it names none.
    fn nv_find(&self, h: u32, n: u8) -> Result<NvRef, Rc> {
        self.persistent.nv.find(h).ok_or(Rc::Fmt1(Fmt1::Handle, Some(At::handle(n))))
    }

    fn nv_name(&self, i: NvRef) -> Name2b {
        self.persistent.nv.get(i).public.name()
    }

    /// An index's own authorization for a read or a write: its authValue where
    /// `TPMA_NV_AUTHREAD` or `AUTHWRITE` allows it, its policy where `POLICYREAD` or
    /// `POLICYWRITE` does, and dictionary-attack protection unless `TPMA_NV_NO_DA`.
    fn authorize_nv(
        &mut self,
        auth: &mut Authorization,
        params: &[u8],
        i: NvRef,
        write: bool,
    ) -> Result<Authorized<NvRef>, Rc> {
        let index = self.persistent.nv.get(i);
        let a = index.public.attributes;
        let name = index.public.name();
        let (value_available, policy_available) = if write {
            (a.auth_write(), a.policy_write())
        } else {
            (a.auth_read(), a.policy_read())
        };
        let entity = EntityAuth {
            name: name.as_slice(),
            value: &index.auth,
            policy: if policy_available { index.public.auth_policy.as_slice() } else { &[] },
            da: if a.no_da() { Da::Exempt } else { Da::Protected },
            value_available,
        };
        auth.authorize(
            &self.stage.reset.sessions,
            params,
            i,
            &entity,
            &mut self.lockout,
            self.stage.pcrs.counter(),
        )
    }

    /// A hierarchy's authorization: its authValue, always available, and no policy.
    fn authorize_hierarchy(
        &mut self,
        auth: &mut Authorization,
        params: &[u8],
        h: HierarchyAuth,
    ) -> Result<Authorized<HierarchyAuth>, Rc> {
        let name = handle_name(h.handle());
        let entity = EntityAuth {
            name: name.as_slice(),
            value: hierarchy_value(&self.persistent, &self.stage.platform_auth, h),
            policy: &[],
            da: hierarchy_da(h),
            value_available: true,
        };
        auth.authorize(
            &self.stage.reset.sessions,
            params,
            h,
            &entity,
            &mut self.lockout,
            self.stage.pcrs.counter(),
        )
    }

    /// `TPM2_EvictControl`, in the reference's order: an object that cannot outlive a reset
    /// (ATTRIBUTES), a persistent object named by another handle (HANDLE), the hierarchy the
    /// authorization may act for (HIERARCHY) and the handle range it owns (RANGE), then a handle
    /// in use (TPM_RC_NV_DEFINED) or no room (TPM_RC_NV_SPACE). A transient object is copied to
    /// `persistent`; a persistent one is removed.
    fn evict_control(
        &mut self,
        provision: HierarchyAuth,
        target: Loaded,
        persistent: u32,
    ) -> Result<(), Rc> {
        let o = self.object(target);
        let evicted = target.is_persistent();
        // The NULL hierarchy's objects are the reference's `temporary` ones.
        if o.hierarchy == Hierarchy::Null || o.public.attributes.st_clear() {
            return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(2))));
        }
        if evicted && target.handle() != persistent {
            return Err(Rc::Fmt1(Fmt1::Handle, Some(At::handle(2))));
        }
        let platform_object = o.hierarchy == Hierarchy::Platform;
        let platform_range = persistent >= object::PLATFORM_PERSISTENT;
        let wrong_hierarchy = match provision {
            HierarchyAuth::Platform => !evicted && !platform_object,
            _ => platform_object,
        };
        if wrong_hierarchy {
            return Err(Rc::Fmt1(Fmt1::Hierarchy, Some(At::handle(2))));
        }
        if !evicted && platform_range != (provision == HierarchyAuth::Platform) {
            return Err(Rc::Fmt1(Fmt1::Range, Some(At::param(1))));
        }
        if evicted {
            self.persistent.evicted.remove(target);
            return Ok(());
        }
        if self.persistent.evicted.contains(persistent) {
            return Err(Fmt0::NvDefined.into());
        }
        if self.persistent.evicted.len() == object::MAX_PERSISTENT_OBJECTS {
            return Err(Fmt0::NvSpace.into());
        }
        let copy = o.duplicate();
        self.persistent.evicted.insert(persistent, copy);
        Ok(())
    }

    /// Every transient slot is taken, counting those this command's persistent objects borrow.
    fn slots_full(&self) -> bool {
        self.stage.objects.loaded_count() + self.stage.borrowed.get() >= object::MAX_LOADED_OBJECTS
    }

    fn object(&self, l: Loaded) -> &Object {
        object::get(&self.stage.objects, &self.persistent.evicted, l)
    }

    /// Checks that an entity handle names something present; returns the object it names, if
    /// it names one.
    fn resolve_entity(&self, e: EntityHandle, n: u8) -> Result<Option<Loaded>, Rc> {
        match e {
            EntityHandle::Hierarchy(_) | EntityHandle::Null | EntityHandle::Pcr(_) => Ok(None),
            EntityHandle::Transient(h) => self.resolve_object(ObjectHandle::Transient(h), n),
            EntityHandle::Persistent(h) => self.resolve_object(ObjectHandle::Persistent(h), n),
            // Binding a session to an NV index is not implemented.
            EntityHandle::NvIndex(_) => Err(Rc::Fmt1(Fmt1::Handle, Some(At::handle(n)))),
        }
    }

    fn resolve_context(&self, c: ContextHandle) -> Result<ContextHandle, Rc> {
        let slot = Slot::new(0).expect("slot 0");
        let present = match c {
            ContextHandle::Transient(h) => self.stage.objects.is_occupied(h),
            ContextHandle::Session(h) => self.stage.reset.sessions.get(h).is_some(),
        };
        if present { Ok(c) } else { Err(Warn::ReferenceH(slot).into()) }
    }

    fn name_of_object(&self, o: Option<Loaded>) -> Name2b {
        match o {
            Some(l) => self.object(l).name(),
            None => handle_name(crate::handle::rh::NULL),
        }
    }

    fn entity_name(&self, e: EntityHandle, loaded: Option<Loaded>) -> Name2b {
        match (e, loaded) {
            (_, Some(l)) => self.object(l).name(),
            (EntityHandle::Hierarchy(h), None) => handle_name(match h {
                HierarchyAuth::Owner => crate::handle::rh::OWNER,
                HierarchyAuth::Endorsement => crate::handle::rh::ENDORSEMENT,
                HierarchyAuth::Platform => crate::handle::rh::PLATFORM,
                HierarchyAuth::Lockout => crate::handle::rh::LOCKOUT,
            }),
            (EntityHandle::Pcr(p), None) => handle_name(u32::from(p.get())),
            (_, None) => handle_name(crate::handle::rh::NULL),
        }
    }

    fn pcr_extend(
        &mut self,
        target: Authorized<PcrOrNull>,
        locality: Locality,
        digests: &[Digest],
    ) -> Result<(), Rc> {
        let PcrOrNull::Pcr(p) = target.entity() else {
            return Ok(());
        };
        if !Pcrs::may_extend(p, locality) {
            return Err(Warn::Locality.into());
        }
        if Pcrs::is_state_saved(p) {
            self.persistent.orderly = None;
        }
        for d in digests {
            self.stage.pcrs.extend(p, d);
        }
        Ok(())
    }

    fn hierarchy_change_auth(&mut self, h: Authorized<HierarchyAuth>, new: AuthValue) {
        let slot = match h.entity() {
            HierarchyAuth::Owner => &mut self.persistent.owner_auth,
            HierarchyAuth::Endorsement => &mut self.persistent.endorsement_auth,
            HierarchyAuth::Lockout => &mut self.persistent.lockout_auth,
            HierarchyAuth::Platform => {
                self.persistent.orderly = None;
                &mut self.stage.platform_auth
            }
        };
        *slot = new;
    }

    #[allow(clippy::too_many_arguments)]
    fn create_primary(
        &mut self,
        hierarchy: Authorized<Hierarchy>,
        sensitive: SensitiveCreate,
        template: crate::types::Public,
        outside: Data2b,
        creation_pcr: List<Selection, 1>,
        locality: Locality,
    ) -> Result<(u32, Writer), Rc> {
        let hierarchy = hierarchy.entity();
        if self.slots_full() {
            return Err(Warn::ObjectMemory.into());
        }
        object::validate_template(&template, sensitive.data.as_slice().len(), None)
            .at(At::param(2))?;
        let name_alg = template.name_alg;
        let object =
            object::create_primary(self.secrets().seed(hierarchy), hierarchy, template, sensitive)
                .map_err(|e| match e {
                    object::Unsupported::Range => Rc::Fmt1(Fmt1::Range, None),
                    object::Unsupported::KeySize => Rc::Fmt1(Fmt1::KeySize, Some(At::param(1))),
                })?;
        let name = object.name();
        let parent = handle_name(hierarchy.handle());
        let mut out = Writer::new();
        Tpm2b(&object.public).write(&mut out);
        let creation = Creation { outside, pcrs: creation_pcr, locality };
        self.write_creation(
            &mut out,
            creation,
            hierarchy,
            name_alg,
            &name,
            (NULL_ALG, &parent, &parent),
        );
        name.write(&mut out);
        let loaded = self.stage.objects.insert(object).expect("a free slot was checked");
        Ok((loaded.handle(), out))
    }

    /// `TPM2B_CREATION_DATA`, the creation hash and the creation ticket of a new object
    /// (`FillInCreationData`, `TicketComputeCreation`), its parent given as its nameAlg, name
    /// and qualified name.
    fn write_creation(
        &self,
        out: &mut Writer,
        c: Creation,
        hierarchy: Hierarchy,
        name_alg: Hash,
        name: &Name2b,
        (parent_name_alg, parent_name, parent_qualified_name): (u16, &Name2b, &Name2b),
    ) {
        let (selection, pcr_digest) = self.stage.pcrs.digest(name_alg, c.pcrs.into_vec());
        let creation = CreationData {
            pcr_select: List::new(selection).expect("at most one selection, as it came in"),
            pcr_digest: Buf::from_slice(pcr_digest.as_slice()).expect("a digest"),
            locality: c.locality.bit(),
            parent_name_alg,
            parent_name: parent_name.clone(),
            parent_qualified_name: parent_qualified_name.clone(),
            outside_info: c.outside,
        };
        let mut marshalled = Writer::new();
        creation.write(&mut marshalled);
        let creation_hash = name_alg.digest(&[&marshalled.into_vec()]);
        let ticket = TkCreation {
            tag: ST_CREATION,
            hierarchy: hierarchy.handle(),
            digest: {
                let d = crypto::hmac(
                    Hash::Sha256,
                    self.secrets().proof(hierarchy),
                    &[&ST_CREATION.to_be_bytes(), name.as_slice(), creation_hash.as_slice()],
                );
                Buf::from_slice(&d).expect("a SHA-256 HMAC")
            },
        };
        Tpm2b(&creation).write(out);
        out.tpm2b(creation_hash.as_slice());
        ticket.write(out);
    }

    /// Checks the session for a loaded object's authorization, by its attributes: the
    /// authValue may be used if userWithAuth is set, the policy if there is one, and failures
    /// count toward lockout unless noDA is set.
    fn authorize_object(
        &mut self,
        auth: &mut Authorization,
        params: &[u8],
        l: Loaded,
    ) -> Result<Authorized<Loaded>, Rc> {
        // The object's own fields, so the lockout state can be borrowed mutably beside them.
        let o = object::get(&self.stage.objects, &self.persistent.evicted, l);
        let a = o.public.attributes;
        let name = o.name();
        let value = AuthValue::from_slice(o.sensitive.auth.as_slice());
        let entity = EntityAuth {
            name: name.as_slice(),
            value: &value,
            policy: o.public.auth_policy.as_slice(),
            da: if a.no_da() { Da::Exempt } else { Da::Protected },
            value_available: a.user_with_auth(),
        };
        auth.authorize(
            &self.stage.reset.sessions,
            params,
            l,
            &entity,
            &mut self.lockout,
            self.stage.pcrs.counter(),
        )
    }

    fn create(
        &mut self,
        platform: &mut impl Platform,
        parent: Authorized<Loaded>,
        sensitive: SensitiveCreate,
        template: crate::types::Public,
        creation: Creation,
    ) -> Result<Writer, Rc> {
        let p = self.object(parent.entity());
        if !object::is_parent(p) {
            return Err(Rc::Fmt1(Fmt1::Type, Some(At::handle(1))));
        }
        if self.slots_full() {
            return Err(Warn::ObjectMemory.into());
        }
        object::validate_template(&template, sensitive.data.as_slice().len(), Some(p))
            .at(At::param(2))?;
        let name_alg = template.name_alg;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        platform.fill_random(&mut seed[..]);
        let mut drbg = crypto::Drbg::new(&seed[..], b"Object Creation", &[]);
        let child = object::create(p, template, sensitive, &mut drbg).map_err(|e| match e {
            object::Unsupported::Range => Rc::Fmt1(Fmt1::Range, None),
            object::Unsupported::KeySize => Rc::Fmt1(Fmt1::KeySize, Some(At::param(1))),
        })?;
        let mut iv = [0u8; 16];
        platform.fill_random(&mut iv);
        let name = child.name();
        let mut out = Writer::new();
        object::wrap(p, &child, iv).write(&mut out);
        Tpm2b(&child.public).write(&mut out);
        let parent_name = p.name();
        self.write_creation(
            &mut out,
            creation,
            p.hierarchy,
            name_alg,
            &name,
            (p.public.name_alg.id(), &parent_name, &p.qualified_name),
        );
        Ok(out)
    }

    fn load(
        &mut self,
        parent: Authorized<Loaded>,
        private: object::Private,
        public: crate::types::Public,
    ) -> Result<(u32, Writer), Rc> {
        if self.slots_full() {
            return Err(Warn::ObjectMemory.into());
        }
        if private.as_slice().is_empty() {
            return Err(Rc::Fmt1(Fmt1::Size, Some(At::param(1))));
        }
        let p = self.object(parent.entity());
        if !object::is_parent(p) {
            return Err(Rc::Fmt1(Fmt1::Type, Some(At::handle(1))));
        }
        let name = public.name();
        let sensitive = object::unwrap(p, &name, private.as_slice(), At::param(1))?;
        let object = object::load(p, public, sensitive, At::param(1), At::param(2))?;
        let loaded = self.stage.objects.insert(object).expect("a free slot was checked");
        let mut out = Writer::new();
        name.write(&mut out);
        Ok((loaded.handle(), out))
    }

    /// The handle of `TPM2_SequenceUpdate` and `TPM2_SequenceComplete`, a `TPMI_DH_OBJECT`:
    /// a running sequence, or a key, which authorizes as itself and is then refused.
    fn sequence_handle(&self, h: u32) -> Result<Result<SequenceSlot, Loaded>, Rc> {
        let o = ObjectHandle::from_handle(h, false).ok_or(Fmt1::Value).at(At::handle(1))?;
        if let ObjectHandle::Transient(t) = o
            && let Some(q) = self.stage.objects.find_sequence(t)
        {
            return Ok(Ok(q));
        }
        Ok(Err(self.resolve_object(o, 1)?.expect("not NULL")))
    }

    /// A sequence's authorization: its authValue is always available, a policy never is, and
    /// it is exempt from dictionary-attack protection (`AllocateSequenceSlot` sets noDA).
    fn authorize_sequence(
        &mut self,
        auth: &mut Authorization,
        params: &[u8],
        q: SequenceSlot,
    ) -> Result<Authorized<SequenceSlot>, Rc> {
        let value = AuthValue::from_slice(self.stage.objects.sequence(q).auth.as_slice());
        let entity = EntityAuth {
            name: &[],
            value: &value,
            policy: &[],
            da: Da::Exempt,
            value_available: true,
        };
        auth.authorize(
            &self.stage.reset.sessions,
            params,
            q,
            &entity,
            &mut self.lockout,
            self.stage.pcrs.counter(),
        )
    }

    /// `TPM2_SequenceComplete`: the digest, a hash-check ticket when the data may be ticketed,
    /// and the sequence flushed.
    fn sequence_complete(
        &mut self,
        q: SequenceSlot,
        data: &[u8],
        hierarchy: Hierarchy,
    ) -> Result<Writer, Rc> {
        let sequence::Kind::Hash { first_block, ticket_safe } = self.stage.objects.sequence(q).kind
        else {
            return Err(Rc::Fmt1(Fmt1::Mode, Some(At::handle(1))));
        };
        let Some(object::Occupant::Sequence(mut done)) = self.stage.objects.remove(q.handle())
        else {
            unreachable!("q names a sequence");
        };
        done.state.update(data);
        let safe = if first_block { ticket_safe } else { sequence::ticket_safe_data(data) };
        let digest = std::mem::take(&mut done.state).finish();
        let mut out = Writer::new();
        out.tpm2b(&digest);
        let ticket = if hierarchy == Hierarchy::Null || !safe {
            HashCheck { hierarchy: crate::handle::rh::NULL, digest: Vec::new() }
        } else {
            HashCheck {
                hierarchy: hierarchy.handle(),
                digest: self.hash_check_hmac(hierarchy, Hash::Sha256, &digest).to_vec(),
            }
        };
        ticket.write(&mut out);
        Ok(out)
    }

    /// A `TPMI_SH_POLICY` handle: `TPM_RC_VALUE` for another handle type,
    /// `TPM_RC_REFERENCE_H0` for a policy session that is not loaded.
    fn policy_session(&self, h: u32) -> Result<u32, Rc> {
        if handle_type(h) != ht::POLICY_SESSION {
            return Err(Rc::Fmt1(Fmt1::Value, Some(At::handle(1))));
        }
        match self.stage.reset.sessions.get(h) {
            Some(Session::Policy(_)) => Ok(h),
            _ => Err(Warn::ReferenceH(Slot::new(0).expect("slot 0")).into()),
        }
    }

    /// The policy commands, each of which updates the policy session's digest and state.
    fn policy(&mut self, cc: Cc, h: u32, params: &[u8]) -> Result<Writer, Rc> {
        let counter = self.stage.pcrs.counter();
        let mut r = Reader::new(params);
        let mut out = Writer::new();
        let code = cc.code().to_be_bytes();
        match cc {
            Cc::PolicyPcr => {
                let expected = Digest2b::read(&mut r).at(At::param(1))?;
                let pcrs = List::<Selection, 1>::read(&mut r).at(At::param(2))?;
                r.finish().map_err(Rc::bare)?;
                let hash = self.policy_mut(h).core.auth_hash;
                let (selection, current) = self.stage.pcrs.digest(hash, pcrs.into_vec());
                let p = self.policy_mut(h);
                let digest = if p.trial {
                    if expected.as_slice().is_empty() {
                        current.as_slice()
                    } else {
                        expected.as_slice()
                    }
                    .to_vec()
                } else {
                    if p.pcr_counter.is_some_and(|c| c != counter) {
                        return Err(Fmt0::PcrChanged.into());
                    }
                    if !expected.as_slice().is_empty() && expected.as_slice() != current.as_slice()
                    {
                        return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1))));
                    }
                    current.as_slice().to_vec()
                };
                let mut marshalled = Writer::new();
                List::<Selection, 1>::new(selection)
                    .expect("at most one selection, as it came in")
                    .write(&mut marshalled);
                p.extend(&[&code, &marshalled.into_vec(), &digest]);
                if !p.trial {
                    p.pcr_counter = Some(counter);
                }
            }
            Cc::PolicyAuthValue | Cc::PolicyPassword => {
                r.finish().map_err(Rc::bare)?;
                let p = self.policy_mut(h);
                // Both record TPM_CC_PolicyAuthValue: the two policies are the same policy,
                // differing only in how the authValue is presented.
                p.extend(&[&Cc::PolicyAuthValue.code().to_be_bytes()]);
                p.auth_value_needed = cc == Cc::PolicyAuthValue;
                p.password_needed = cc == Cc::PolicyPassword;
            }
            Cc::PolicyCommandCode => {
                let target = r.u32().at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let p = self.policy_mut(h);
                if p.command_code.is_some_and(|c| c != target) {
                    return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1))));
                }
                if Cc::from_code(target).is_none() {
                    return Err(Rc::Fmt1(Fmt1::PolicyCc, Some(At::param(1))));
                }
                p.extend(&[&code, &target.to_be_bytes()]);
                p.command_code = Some(target);
            }
            Cc::PolicyRestart => {
                r.finish().map_err(Rc::bare)?;
                self.policy_mut(h).restart();
            }
            Cc::PolicyGetDigest => {
                r.finish().map_err(Rc::bare)?;
                out.tpm2b(&self.policy_mut(h).digest);
            }
            _ => unreachable!("{cc:?} is not a policy command"),
        }
        Ok(out)
    }

    fn policy_mut(&mut self, h: u32) -> &mut session::PolicySession {
        match self.stage.reset.sessions.get_mut(h) {
            Some(Session::Policy(p)) => p,
            _ => unreachable!("policy_session() checked {h:#x}"),
        }
    }

    /// `TPMT_TK_HASHCHECK` for a digest of `data` (`TicketComputeHashCheck`): a NULL ticket under
    /// the NULL hierarchy, or when the data could be passed off as something the TPM produced
    /// (it starts with `TPM_GENERATED_VALUE`).
    fn hash_check(
        &self,
        hierarchy: Hierarchy,
        hash: Hash,
        digest: &[u8],
        data: &[u8],
    ) -> HashCheck {
        if hierarchy == Hierarchy::Null || data.starts_with(&TPM_GENERATED_VALUE.to_be_bytes()) {
            return HashCheck { hierarchy: crate::handle::rh::NULL, digest: Vec::new() };
        }
        HashCheck {
            hierarchy: hierarchy.handle(),
            digest: self.hash_check_hmac(hierarchy, hash, digest).to_vec(),
        }
    }

    /// The HMAC a hash-check ticket carries, under any hierarchy's proof, the NULL hierarchy's
    /// included: `TPM2_Sign` recomputes it to check a ticket it is shown.
    fn hash_check_hmac(
        &self,
        hierarchy: Hierarchy,
        hash: Hash,
        digest: &[u8],
    ) -> zeroize::Zeroizing<Vec<u8>> {
        crypto::hmac(
            Hash::Sha256,
            self.secrets().proof(hierarchy),
            &[&ST_HASHCHECK.to_be_bytes(), &hash.id().to_be_bytes(), digest],
        )
    }

    /// `TPM2_Sign`, in the reference's order: a key that can sign (`TPM_RC_KEY`), not one
    /// restricted to certificates (`TPM_RC_ATTRIBUTES`), a scheme the key allows
    /// (`TPM_RC_SCHEME`), then a ticket that proves the TPM hashed the data when the key is
    /// restricted or one is offered (`TPM_RC_TICKET`), or else a digest of the scheme's size.
    fn sign(
        &self,
        platform: &mut impl Platform,
        key: Loaded,
        digest: &[u8],
        scheme: SigScheme,
        ticket: HashCheckTicket,
    ) -> Result<Writer, Rc> {
        let o = self.object(key);
        let a = o.public.attributes;
        if !a.sign_encrypt() || matches!(o.public.kind, PublicKind::SymCipher(_)) {
            return Err(Rc::Fmt1(Fmt1::Key, Some(At::handle(1))));
        }
        if a.x509sign() {
            return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(1))));
        }
        let scheme = sign_scheme(&o.public.kind, scheme)
            .ok_or(Rc::Fmt1(Fmt1::Scheme, Some(At::param(2))))?;
        let hash = scheme.1;
        if !ticket.digest.as_slice().is_empty() || a.restricted() {
            let expected = self.hash_check_hmac(ticket.hierarchy, hash, digest);
            if !crypto::constant_time_eq(&expected, ticket.digest.as_slice()) {
                return Err(Rc::Fmt1(Fmt1::Ticket, Some(At::param(3))));
            }
        } else if digest.len() != hash.size() {
            return Err(Rc::Fmt1(Fmt1::Size, Some(At::param(1))));
        }
        let mut out = Writer::new();
        out.u16(scheme.0);
        hash.write(&mut out);
        match scheme.0 {
            crate::alg::id::RSASSA | crate::alg::id::RSAPSS => {
                let pss = scheme.0 == crate::alg::id::RSAPSS;
                let sig = o
                    .rsa()
                    .expect("an RSA scheme is only selected for an RSA key")
                    .sign(&mut crypto::PlatformRng::seeded(platform), pss, digest)
                    .ok_or(Fmt1::Value)
                    .map_err(Rc::bare)?;
                out.tpm2b(&sig);
            }
            crate::alg::id::ECDSA => {
                let digest: &[u8; 32] =
                    digest.try_into().map_err(|_| Rc::Fmt1(Fmt1::Size, Some(At::param(1))))?;
                let (r, s) = o.ecc().expect("ECDSA is only selected for an ECC key").sign(digest);
                out.tpm2b(&r);
                out.tpm2b(&s);
            }
            crate::alg::id::HMAC => {
                let SensitiveKind::KeyedHash(k) = &o.sensitive.kind else {
                    unreachable!("HMAC is only selected for a keyed-hash key");
                };
                out.bytes(&crypto::hmac(hash, k.as_slice(), &[digest]));
            }
            other => unreachable!("sign_scheme() selected {other:#x}"),
        }
        Ok(out)
    }

    /// `TPM2_RSA_Decrypt`, in the reference's order.
    fn rsa_decrypt(
        &self,
        platform: &mut impl Platform,
        key: Loaded,
        c: &[u8],
        scheme: RsaDecryptScheme,
        label: &[u8],
    ) -> Result<Writer, Rc> {
        let o = self.object(key);
        let PublicKind::Rsa(r) = &o.public.kind else {
            return Err(Rc::Fmt1(Fmt1::Key, Some(At::handle(1))));
        };
        let a = o.public.attributes;
        if a.restricted() || !a.decrypt() {
            return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(1))));
        }
        // IsLabelProperlyFormatted: empty, or ending in its NUL.
        if label.last().is_some_and(|b| *b != 0) {
            return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(3))));
        }
        // CryptRsaSelectScheme: the key's scheme wins where the caller names none; where both
        // name one, they must agree.
        let keys = match r.parms.scheme {
            RsaScheme::Null(()) => None,
            RsaScheme::Rsaes(()) => Some(RsaDecryptScheme::Rsaes(())),
            RsaScheme::Oaep(h) => Some(RsaDecryptScheme::Oaep(h)),
            RsaScheme::Rsassa(_) | RsaScheme::Rsapss(_) => {
                return Err(Rc::Fmt1(Fmt1::Scheme, Some(At::param(2))));
            }
        };
        let scheme = match (keys, scheme) {
            (None, s) | (Some(s), RsaDecryptScheme::Null(())) => s,
            (Some(k), s) if k == s => s,
            _ => return Err(Rc::Fmt1(Fmt1::Scheme, Some(At::param(2)))),
        };
        let scheme = match scheme {
            RsaDecryptScheme::Null(()) => crypto::RsaDecrypt::Raw,
            RsaDecryptScheme::Rsaes(()) => crypto::RsaDecrypt::Pkcs1,
            RsaDecryptScheme::Oaep(_) => crypto::RsaDecrypt::Oaep(label),
        };
        let m = o
            .rsa()
            .expect("an RSA object")
            .decrypt(&mut crypto::PlatformRng::seeded(platform), scheme, c)
            .map_err(|e| match e {
                crypto::RsaDecryptError::Size => Rc::Fmt1(Fmt1::Size, None),
                crypto::RsaDecryptError::Value => Rc::Fmt1(Fmt1::Value, None),
            })?;
        let mut out = Writer::new();
        out.tpm2b(&m);
        Ok(out)
    }

    fn start_auth_session(
        &mut self,
        platform: &mut impl Platform,
        tpm_key: Option<Loaded>,
        bind: EntityHandle,
        bind_loaded: Option<Loaded>,
        input: StartAuthSessionIn,
    ) -> Result<(u32, Writer), Rc> {
        let nonce = input.nonce_caller.as_slice();
        if nonce.len() < 16 || nonce.len() > input.auth_hash.size() {
            return Err(Rc::Fmt1(Fmt1::Size, Some(At::param(1))));
        }
        let salt = match tpm_key {
            Some(k) => {
                let key = self.object(k);
                if !matches!(key.public.kind, PublicKind::Ecc(_) | PublicKind::Rsa(_)) {
                    return Err(Rc::Fmt1(Fmt1::Key, Some(At::handle(1))));
                }
                if input.encrypted_salt.as_slice().is_empty() {
                    return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(2))));
                }
                if !key.public.attributes.decrypt() {
                    return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(1))));
                }
                // CryptSecretDecrypt; any failure is TPM_RC_VALUE on the salt.
                let salt = match &key.public.kind {
                    PublicKind::Ecc(ecc) => ecc_salt(
                        key.public.name_alg,
                        &key.ecc().expect("an ECC object"),
                        &ecc.unique,
                        input.encrypted_salt.as_slice(),
                    ),
                    PublicKind::Rsa(r) => match r.parms.scheme {
                        // The key's own scheme, OAEP over its nameAlg if it has none.
                        RsaScheme::Null(()) | RsaScheme::Oaep(_) => key
                            .rsa()
                            .expect("an RSA object")
                            .decrypt(
                                &mut crypto::PlatformRng::seeded(platform),
                                crypto::RsaDecrypt::Oaep(SECRET_LABEL),
                                input.encrypted_salt.as_slice(),
                            )
                            .ok()
                            .filter(|s| s.len() <= key.public.name_alg.size()),
                        _ => None,
                    },
                    _ => unreachable!("checked above"),
                };
                salt.ok_or(Rc::Fmt1(Fmt1::Value, Some(At::param(2))))?
            }
            None => {
                if !input.encrypted_salt.as_slice().is_empty() {
                    return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(2))));
                }
                zeroize::Zeroizing::new(Vec::new())
            }
        };
        let bind_auth = match (bind, bind_loaded) {
            (EntityHandle::Null, _) => None,
            (_, Some(l)) => {
                let o = self.object(l);
                let da = if o.public.attributes.no_da() { Da::Exempt } else { Da::Protected };
                Some((o.name(), AuthValue::from_slice(o.sensitive.auth.as_slice()), da))
            }
            (EntityHandle::Hierarchy(h), None) => {
                let v = hierarchy_value(&self.persistent, &self.stage.platform_auth, h);
                Some((
                    self.entity_name(bind, None),
                    AuthValue::from_slice(v.key_material()),
                    hierarchy_da(h),
                ))
            }
            (EntityHandle::Pcr(_), None) => {
                Some((self.entity_name(bind, None), AuthValue::empty(), Da::Exempt))
            }
            (
                EntityHandle::Transient(_) | EntityHandle::Persistent(_) | EntityHandle::NvIndex(_),
                None,
            ) => {
                unreachable!("resolve_entity refused what is not loaded")
            }
        };
        let session = session::start(
            platform,
            input.session_type,
            input.auth_hash,
            nonce,
            input.symmetric,
            bind_auth.as_ref().map(|(n, v, d)| (n.as_slice(), v, *d)),
            &salt,
        );
        let nonce_tpm = session.core().nonce_tpm.clone();
        let handle = self.stage.reset.sessions.create(session)?;
        let mut out = Writer::new();
        nonce_tpm.write(&mut out);
        Ok((handle, out))
    }

    fn context_save(&mut self, target: ContextHandle, h: u32) -> Result<Writer, Rc> {
        let (context, clear_orderly) = match target {
            ContextHandle::Transient(_) => {
                let sequence =
                    self.stage.reset.object_sequence.checked_add(1).ok_or(Fmt0::TooManyContexts)?;
                self.stage.reset.object_sequence = sequence;
                let context = if let Some(l) = self.stage.objects.find(h) {
                    let o = self.object(l);
                    let saved_handle = if o.public.attributes.st_clear() {
                        SavedHandle::StClear
                    } else {
                        SavedHandle::Object
                    };
                    let blob = context::seal(
                        self.secrets().proof(o.hierarchy),
                        &self.epoch(),
                        sequence,
                        saved_handle,
                        o,
                    );
                    Context { sequence, saved_handle, hierarchy: o.hierarchy, blob }
                } else {
                    // A sequence belongs to no hierarchy; its context is sealed under the NULL
                    // hierarchy's proof, so it does not outlive a TPM Reset.
                    let q = self.stage.objects.find_sequence(h).expect("resolved");
                    let blob = context::seal(
                        self.secrets().proof(Hierarchy::Null),
                        &self.epoch(),
                        sequence,
                        SavedHandle::Sequence,
                        self.stage.objects.sequence(q),
                    );
                    Context {
                        sequence,
                        saved_handle: SavedHandle::Sequence,
                        hierarchy: Hierarchy::Null,
                        blob,
                    }
                };
                (context, true)
            }
            ContextHandle::Session(h) => {
                let (sequence, session) = self.stage.reset.sessions.save(h)?;
                let saved_handle = SavedHandle::Session(h);
                let blob = context::seal(
                    self.secrets().proof(Hierarchy::Null),
                    &self.epoch(),
                    sequence,
                    saved_handle,
                    &*session,
                );
                (Context { sequence, saved_handle, hierarchy: Hierarchy::Null, blob }, true)
            }
        };
        if clear_orderly {
            self.persistent.orderly = None;
        }
        let mut out = Writer::new();
        context.write(&mut out);
        Ok(out)
    }

    fn context_load(&mut self, context: Context) -> Result<u32, Rc> {
        let at = At::param(1);
        let proof = self.secrets().proof(context.hierarchy);
        let epoch = self.epoch();
        match context.saved_handle {
            SavedHandle::Object | SavedHandle::StClear => {
                let o: Object = context::open(proof, &epoch, &context).at(at)?;
                let l = self.stage.objects.insert(o).ok_or(Warn::ObjectMemory)?;
                Ok(l.handle())
            }
            SavedHandle::Sequence => {
                let q: HashSequence = context::open(proof, &epoch, &context).at(at)?;
                let l = self.stage.objects.insert_sequence(q).ok_or(Warn::ObjectMemory)?;
                Ok(l.handle())
            }
            SavedHandle::Session(h) => {
                let s: Session = context::open(proof, &epoch, &context).at(at)?;
                self.persistent.orderly = None;
                self.stage.reset.sessions.restore(h, context.sequence, s)?;
                Ok(h)
            }
        }
    }

    fn flush_context(&mut self, target: ContextHandle) -> Result<(), Rc> {
        let refused = Rc::Fmt1(Fmt1::Handle, Some(At::param(1)));
        match target {
            ContextHandle::Transient(h) => {
                self.stage.objects.remove(h).ok_or(refused)?;
            }
            ContextHandle::Session(h) => {
                if !self.stage.reset.sessions.flush(h) {
                    return Err(refused);
                }
            }
        }
        Ok(())
    }
}

/// The scheme a signature is made under (`CryptSelectSignScheme`, `CryptIsValidSignScheme`):
/// the key's own where the caller names NULL, the caller's where the key has none, and where
/// both name one they must agree; it must also suit the key's type. As `(TPM_ALG_ID, hash)`.
fn sign_scheme(kind: &PublicKind, asked: SigScheme) -> Option<(u16, Hash)> {
    use crate::alg::id;
    let keys = match kind {
        PublicKind::Rsa(r) => match r.parms.scheme {
            RsaScheme::Null(()) => None,
            RsaScheme::Rsassa(h) => Some(SigScheme::Rsassa(h)),
            RsaScheme::Rsapss(h) => Some(SigScheme::Rsapss(h)),
            RsaScheme::Rsaes(()) | RsaScheme::Oaep(_) => return None,
        },
        PublicKind::Ecc(e) => match e.parms.scheme {
            EccScheme::Null(()) => None,
            EccScheme::Ecdsa(h) => Some(SigScheme::Ecdsa(h)),
            EccScheme::Ecdh(_) => return None,
        },
        PublicKind::KeyedHash(k) => match k.scheme {
            KeyedHashScheme::Null(()) => None,
            KeyedHashScheme::Hmac(h) => Some(SigScheme::Hmac(h)),
        },
        PublicKind::SymCipher(_) => return None,
    };
    let scheme = match (keys, asked) {
        (None, SigScheme::Null(())) => return None,
        (None, s) | (Some(s), SigScheme::Null(())) => s,
        (Some(k), s) if k == s => s,
        _ => return None,
    };
    match (kind, scheme) {
        (PublicKind::Rsa(_), SigScheme::Rsassa(h)) => Some((id::RSASSA, h)),
        (PublicKind::Rsa(_), SigScheme::Rsapss(h)) => Some((id::RSAPSS, h)),
        (PublicKind::Ecc(_), SigScheme::Ecdsa(h)) => Some((id::ECDSA, h)),
        (PublicKind::KeyedHash(_), SigScheme::Hmac(h)) => Some((id::HMAC, h)),
        _ => None,
    }
}

/// The salt of a session salted to an ECC key: the secret is a point `QeU`, and the salt is
/// `KDFe(nameAlg, (d × QeU).x, "SECRET", QeU.x, key.x, digest bits)`. `None` for a secret that
/// is not a well-formed point on the curve.
fn ecc_salt(
    name_alg: Hash,
    key: &EccPrivate,
    public: &EccPoint,
    secret: &[u8],
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let mut r = Reader::new(secret);
    let point = EccPoint::read(&mut r).ok()?;
    r.finish().ok()?;
    let peer = EccPublicKey::from_coordinates(point.x.as_slice(), point.y.as_slice())?;
    let z = key.ecdh(&peer);
    Some(crypto::kdfe(
        name_alg,
        &z[..],
        b"SECRET",
        point.x.as_slice(),
        public.x.as_slice(),
        (name_alg.size() * 8) as u32,
    ))
}

/// A `TPML_DIGEST_VALUES`: at most one digest per implemented hash.
fn read_digest_values(r: &mut Reader<'_>) -> Result<Vec<Digest>, Fmt1> {
    let count = r.u32()?;
    if count as usize > crate::alg::HASHES.len() {
        return Err(Fmt1::Size);
    }
    (0..count).map(|_| Digest::read_tagged(r)).collect()
}
