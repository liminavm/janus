// SPDX-License-Identifier: MIT OR Apache-2.0

//! The engine and its lifecycle.
//!
//! After `_TPM_Init` a TPM accepts only `TPM2_Startup`; after it, everything but `TPM2_Startup`.
//! The two are different types here, [`Tpm<Initialized>`] and [`Tpm<Running>`], and only the
//! running one has PCRs or a platform authorization to act on. A command that needs them cannot
//! be dispatched before Startup, because there is nothing to dispatch it to.

use crate::alg::{Digest, MAX_DIGEST};
use crate::capability::{self, Variable};
use crate::cc::Cc;
use crate::command::{self, Command};
use crate::handle::{HierarchyAuth, PcrOrNull};
use crate::pcr::{self, Pcrs};
use crate::rc::{At, Fmt1, Rc, Warn};
use crate::session::{AuthValue, Authorized, Entity, Lockout};
use crate::wire::{Blame as _, Reader, Writer};
use crate::{Locality, Platform};

/// What survives `_TPM_Init`: the state a real TPM keeps in NV.
struct Persistent {
    owner_auth: AuthValue,
    endorsement_auth: AuthValue,
    lockout_auth: AuthValue,
    lockout: Lockout,
    /// What `TPM2_Shutdown(STATE)` saved for the next `TPM2_Startup(STATE)`. Taken by the next
    /// Startup of either kind, so a resume can only follow the shutdown that prepared it.
    saved: Option<Box<Saved>>,
}

struct Saved {
    pcrs: Pcrs,
}

/// After `_TPM_Init`, before `TPM2_Startup`.
pub struct Initialized;

/// After `TPM2_Startup`.
pub struct Running {
    pcrs: Pcrs,
    /// Set to the empty value by every Startup.
    platform_auth: AuthValue,
    /// `TPM2_Shutdown` has run since Startup (`TPMA_STARTUP_CLEAR.orderly`).
    shut_down: bool,
}

pub struct Tpm<S> {
    persistent: Persistent,
    stage: S,
}

enum Lifecycle {
    Initialized(Tpm<Initialized>),
    // Boxed: the running TPM carries its PCR bank, the initialized one does not.
    Running(Box<Tpm<Running>>),
}

/// A TPM 2.0. The device that owns it delivers each command with the locality it arrived at,
/// and calls [`Janus::init`] on a platform reset.
pub struct Janus<P: Platform> {
    platform: P,
    /// `None` only while a command is moving the TPM between stages.
    lifecycle: Option<Lifecycle>,
}

impl<P: Platform> Janus<P> {
    /// A newly manufactured TPM, as after `_TPM_Init`: empty authorization values, waiting for
    /// `TPM2_Startup`.
    pub fn manufacture(platform: P) -> Self {
        let persistent = Persistent {
            owner_auth: AuthValue::empty(),
            endorsement_auth: AuthValue::empty(),
            lockout_auth: AuthValue::empty(),
            lockout: Lockout { lockout_auth_failed: false },
            saved: None,
        };
        Janus {
            platform,
            lifecycle: Some(Lifecycle::Initialized(Tpm { persistent, stage: Initialized })),
        }
    }

    /// `_TPM_Init`: the platform was reset. Everything that does not survive a power cycle is
    /// gone, and the TPM waits for `TPM2_Startup` again.
    pub fn init(&mut self) {
        let next = match self.lifecycle.take().expect("the TPM is between stages") {
            Lifecycle::Initialized(t) => t,
            Lifecycle::Running(t) => Tpm { persistent: t.persistent, stage: Initialized },
        };
        self.lifecycle = Some(Lifecycle::Initialized(next));
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
        let cmd = command::frame(bytes)?;
        let (next, result) = match self.lifecycle.take().expect("the TPM is between stages") {
            Lifecycle::Initialized(tpm) if cmd.cc == Cc::Startup => {
                match tpm.startup(locality, cmd) {
                    Ok((running, response)) => {
                        (Lifecycle::Running(Box::new(running)), Ok(response))
                    }
                    Err(refused) => {
                        let (tpm, rc) = *refused;
                        (Lifecycle::Initialized(tpm), Err(rc))
                    }
                }
            }
            Lifecycle::Initialized(tpm) => {
                (Lifecycle::Initialized(tpm), Err(crate::rc::Fmt0::Initialize.into()))
            }
            Lifecycle::Running(tpm) if cmd.cc == Cc::Startup => {
                (Lifecycle::Running(tpm), Err(crate::rc::Fmt0::Initialize.into()))
            }
            Lifecycle::Running(mut tpm) => {
                let r = tpm.execute(&mut self.platform, locality, cmd);
                (Lifecycle::Running(tpm), r)
            }
        };
        self.lifecycle = Some(next);
        result
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
        locality: Locality,
        mut cmd: Command<'_>,
    ) -> Result<(Tpm<Running>, Vec<u8>), Box<Refused>> {
        let parsed = (|| {
            let auth = cmd.auth_area()?;
            let kind = StartupType::read(&mut cmd.body).at(At::param(1))?;
            Ok((auth, kind))
        })();
        let (auth, kind) = match parsed {
            Ok(p) => p,
            Err(rc) => return Err(Box::new((self, rc))),
        };
        let tag = cmd.tag;
        if let Err(rc) = cmd.finish() {
            return Err(Box::new((self, rc)));
        }
        let pcrs = match (kind, self.persistent.saved.take()) {
            (StartupType::State, Some(saved)) => Pcrs::resume(&saved.pcrs, locality),
            (StartupType::State, None) => {
                return Err(Box::new((self, Rc::Fmt1(Fmt1::Value, Some(At::param(1))))));
            }
            (StartupType::Clear, _) => Pcrs::reset(locality),
        };
        let running = Tpm {
            persistent: self.persistent,
            stage: Running { pcrs, platform_auth: AuthValue::empty(), shut_down: false },
        };
        Ok((running, command::success(tag, Writer::new(), &auth)))
    }
}

impl Entity for PcrOrNull {
    fn da_exempt(&self) -> bool {
        true
    }
}

impl Entity for HierarchyAuth {
    fn da_exempt(&self) -> bool {
        *self != HierarchyAuth::Lockout
    }
}

impl Tpm<Running> {
    fn execute(
        &mut self,
        platform: &mut impl Platform,
        locality: Locality,
        mut cmd: Command<'_>,
    ) -> Result<Vec<u8>, Rc> {
        let mut out = Writer::new();
        let tag = cmd.tag;
        let auth = match cmd.cc {
            Cc::Startup => unreachable!("Startup is dispatched to an initialized TPM"),
            Cc::Shutdown => {
                let auth = cmd.auth_area()?;
                let kind = StartupType::read(&mut cmd.body).at(At::param(1))?;
                self.shutdown(kind);
                auth
            }
            Cc::SelfTest => {
                let auth = cmd.auth_area()?;
                match cmd.body.u8().at(At::param(1))? {
                    0 | 1 => {}
                    _ => return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1)))),
                }
                auth
            }
            Cc::GetCapability => {
                let auth = cmd.auth_area()?;
                let capability = cmd.body.u32().at(At::param(1))?;
                let property = cmd.body.u32().at(At::param(2))?;
                let count = cmd.body.u32().at(At::param(3))?;
                capability::get(capability, property, count, &self.variable(), &mut out)?;
                auth
            }
            Cc::GetRandom => {
                let auth = cmd.auth_area()?;
                let requested = cmd.body.u16().at(At::param(1))?;
                let mut bytes = vec![0u8; usize::from(requested).min(MAX_DIGEST)];
                platform.fill_random(&mut bytes);
                out.tpm2b(&bytes);
                auth
            }
            Cc::PcrRead => {
                let auth = cmd.auth_area()?;
                let selection = pcr::read_selection_list(&mut cmd.body).at(At::param(1))?;
                let (counter, selection, digests) = self.stage.pcrs.read(selection);
                out.u32(counter);
                pcr::write_selection_list(&mut out, &selection);
                out.u32(digests.len() as u32);
                for d in &digests {
                    out.tpm2b(d.as_slice());
                }
                auth
            }
            Cc::PcrExtend => {
                let handle = cmd.body.u32().at(At::handle(1))?;
                let target = PcrOrNull::from_handle(handle).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = cmd.auth_area()?;
                let target = auth.authorize(
                    target,
                    &AuthValue::empty(),
                    &mut self.persistent.lockout,
                    false,
                )?;
                let digests = read_digest_values(&mut cmd.body).at(At::param(1))?;
                self.pcr_extend(target, locality, &digests)?;
                auth
            }
            Cc::HierarchyChangeAuth => {
                let handle = cmd.body.u32().at(At::handle(1))?;
                let hierarchy =
                    HierarchyAuth::from_handle(handle).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = cmd.auth_area()?;
                let Persistent { owner_auth, endorsement_auth, lockout_auth, lockout, .. } =
                    &mut self.persistent;
                let current = match hierarchy {
                    HierarchyAuth::Owner => &*owner_auth,
                    HierarchyAuth::Endorsement => &*endorsement_auth,
                    HierarchyAuth::Lockout => &*lockout_auth,
                    HierarchyAuth::Platform => &self.stage.platform_auth,
                };
                let is_lockout = hierarchy == HierarchyAuth::Lockout;
                let hierarchy = auth.authorize(hierarchy, current, lockout, is_lockout)?;
                let new = AuthValue::from_wire(cmd.body.tpm2b::<MAX_DIGEST>().at(At::param(1))?);
                self.hierarchy_change_auth(hierarchy, new);
                auth
            }
        };
        cmd.finish()?;
        Ok(command::success(tag, out, &auth))
    }

    fn variable(&self) -> Variable {
        let p = &self.persistent;
        Variable {
            owner_auth_set: !p.owner_auth.is_empty(),
            endorsement_auth_set: !p.endorsement_auth.is_empty(),
            lockout_auth_set: !p.lockout_auth.is_empty(),
            orderly: self.stage.shut_down,
        }
    }

    fn shutdown(&mut self, kind: StartupType) {
        self.persistent.saved = match kind {
            StartupType::State => Some(Box::new(Saved { pcrs: self.stage.pcrs.clone() })),
            StartupType::Clear => None,
        };
        self.stage.shut_down = true;
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
            HierarchyAuth::Platform => &mut self.stage.platform_auth,
        };
        *slot = new;
    }
}

/// A `TPML_DIGEST_VALUES`: at most one digest per implemented hash.
fn read_digest_values(r: &mut Reader<'_>) -> Result<Vec<Digest>, Fmt1> {
    let count = r.u32()?;
    if count as usize > crate::alg::HASHES.len() {
        return Err(Fmt1::Size);
    }
    (0..count).map(|_| Digest::read_tagged(r)).collect()
}
