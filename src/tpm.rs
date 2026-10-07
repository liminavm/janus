// SPDX-License-Identifier: MIT OR Apache-2.0

//! The engine and its lifecycle.
//!
//! After `_TPM_Init` a TPM accepts only `TPM2_Startup`; after it, everything but `TPM2_Startup`.
//! The two are different types here, [`Tpm<Initialized>`] and [`Tpm<Running>`], and only the
//! running one has PCRs, objects or a platform authorization to act on. A command that needs
//! them cannot be dispatched before Startup, because there is nothing to dispatch it to.
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
use crate::handle::{ContextHandle, EntityHandle, HierarchyAuth, ObjectHandle, PcrOrNull};
use crate::hierarchy::{Hierarchy, NullSecrets, PersistentSecrets, Secrets};
use crate::marshal::{List, Marshal, Tpm2b, Unmarshal};
use crate::object::{self, Loaded, Object, Objects, SensitiveKind};
use crate::pcr::{self, Pcrs, Selection};
use crate::rc::{At, Fmt0, Fmt1, Rc, Slot, Warn};
use crate::session::{
    self, AuthValue, Authorization, Authorized, Da, Entity, EntityAuth, Lockout, Session,
    SessionTable, SessionType,
};
use crate::types::{
    CreationData, Data2b, EccPoint, Name2b, PublicKind, SensitiveCreate, SymDef, TkCreation,
};
use crate::wire::{Blame as _, Buf, Reader, Writer};
use crate::{Locality, Platform};

/// What survives `_TPM_Init`: the state a real TPM keeps in NV.
struct Persistent {
    owner_auth: AuthValue,
    endorsement_auth: AuthValue,
    lockout_auth: AuthValue,
    secrets: PersistentSecrets,
    /// TPM Resets since manufacture (`totalResetCount`). Saved contexts are bound to it.
    reset_count: u64,
    /// The last `TPM2_Shutdown`, until a Startup takes it or a command makes it stale.
    orderly: Option<Orderly>,
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
    /// The sequence the last saved object context got (`objectContextID`).
    object_sequence: u64,
}

impl ResetState {
    fn new(platform: &mut impl Platform) -> ResetState {
        ResetState {
            null: NullSecrets::generate(platform),
            sessions: SessionTable::default(),
            clear_count: 0,
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
}

pub struct Tpm<S> {
    persistent: Persistent,
    /// Kept apart from [`Persistent`] so the authorization check can update it while it reads
    /// an authorization value from there.
    lockout: Lockout,
    stage: S,
}

enum Lifecycle {
    // Boxed, both: each carries the persistent state, and the running one its PCR bank and
    // objects too.
    Initialized(Box<Tpm<Initialized>>),
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
    /// A newly manufactured TPM, as after `_TPM_Init`: new primary seeds and proofs, empty
    /// authorization values, waiting for `TPM2_Startup`.
    pub fn manufacture(mut platform: P) -> Self {
        let persistent = Persistent {
            owner_auth: AuthValue::empty(),
            endorsement_auth: AuthValue::empty(),
            lockout_auth: AuthValue::empty(),
            secrets: PersistentSecrets::generate(&mut platform),
            reset_count: 0,
            orderly: None,
        };
        let tpm = Tpm {
            persistent,
            lockout: Lockout { lockout_auth_failed: false },
            stage: Initialized { carried: None },
        };
        Janus { platform, lifecycle: Some(Lifecycle::Initialized(Box::new(tpm))) }
    }

    /// `_TPM_Init`: the platform was reset. Everything that does not survive a power cycle is
    /// gone, and the TPM waits for `TPM2_Startup` again.
    pub fn init(&mut self) {
        let next = match self.lifecycle.take().expect("the TPM is between stages") {
            Lifecycle::Initialized(t) => t,
            Lifecycle::Running(t) => {
                let Tpm { persistent, lockout, stage } = *t;
                let Running { platform_auth, mut reset, .. } = stage;
                reset.sessions.drop_loaded();
                let carried = Some(Box::new(Carried { platform_auth, reset }));
                Box::new(Tpm { persistent, lockout, stage: Initialized { carried } })
            }
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
        let orderly = self.persistent.orderly.take();
        let carried = self.stage.carried.take();
        let (pcrs, platform_auth, reset) = match (kind, orderly, carried) {
            (StartupType::State, Some(Orderly::State(saved)), Some(c)) => {
                (Pcrs::resume(&saved, locality), c.platform_auth, c.reset)
            }
            (StartupType::State, _, _) => {
                return Err(Box::new((self, Rc::Fmt1(Fmt1::Value, Some(At::param(1))))));
            }
            (StartupType::Clear, Some(Orderly::State(saved)), Some(c)) => {
                let mut reset = c.reset;
                reset.clear_count = reset.clear_count.wrapping_add(1);
                (Pcrs::restart(&saved, locality), AuthValue::empty(), reset)
            }
            (StartupType::Clear, _, _) => {
                self.persistent.reset_count += 1;
                (Pcrs::reset(locality), AuthValue::empty(), ResetState::new(platform))
            }
        };
        let running = Tpm {
            persistent: self.persistent,
            lockout: self.lockout,
            stage: Running { pcrs, platform_auth, reset, objects: Objects::default() },
        };
        Ok((running, command::success(tag, None, &[], &[])))
    }
}

impl Entity for PcrOrNull {}
impl Entity for HierarchyAuth {}
impl Entity for Hierarchy {}
impl Entity for Loaded {}

/// A handle's name for the cpHash: an object's is its name, everything else's is its handle.
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

impl Tpm<Running> {
    fn execute(
        &mut self,
        platform: &mut impl Platform,
        locality: Locality,
        mut cmd: Command<'_>,
    ) -> Result<Vec<u8>, Rc> {
        let tag = cmd.tag;
        let cc = cmd.cc;
        let attributes = cc.attributes();
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
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let kind = StartupType::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.persistent.orderly = Some(match kind {
                    StartupType::State => Orderly::State(Box::new(self.stage.pcrs.clone())),
                    StartupType::Clear => Orderly::Clear,
                });
                (None, Writer::new(), auth)
            }
            Cc::SelfTest => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                bool::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                (None, Writer::new(), auth)
            }
            Cc::GetCapability => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
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
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let requested = r.u16().at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let mut bytes = vec![0u8; usize::from(requested).min(MAX_DIGEST)];
                platform.fill_random(&mut bytes);
                let mut out = Writer::new();
                out.tpm2b(&bytes);
                (None, out, auth)
            }
            Cc::PcrRead => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
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
                )?;
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let digests = read_digest_values(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.pcr_extend(target, locality, &digests)?;
                (None, Writer::new(), auth)
            }
            Cc::HierarchyChangeAuth => {
                let [h] = cmd.handles()?;
                let hierarchy =
                    HierarchyAuth::from_handle(h).ok_or(Fmt1::Value).at(At::handle(1))?;
                let mut auth = self.read_auth(&mut cmd, vec![handle_name(h)])?;
                let raw = cmd.params();
                let entity = EntityAuth {
                    name: &h.to_be_bytes(),
                    value: hierarchy_value(&self.persistent, &self.stage.platform_auth, hierarchy),
                    policy: &[],
                    da: hierarchy_da(hierarchy),
                    value_available: true,
                };
                let hierarchy = auth.authorize(
                    &self.stage.reset.sessions,
                    raw,
                    hierarchy,
                    &entity,
                    &mut self.lockout,
                )?;
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let new = AuthValue::from_wire(r.tpm2b::<MAX_DIGEST>().at(At::param(1))?);
                r.finish().map_err(Rc::bare)?;
                // The response is computed with the new value (EntityGetAuthValue runs after
                // the command).
                auth.set_response_auth(0, &new);
                self.hierarchy_change_auth(hierarchy, new);
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
                )?;
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
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
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let o = self.stage.objects.get(target.expect("ReadPublic refuses NULL"));
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
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
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
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                Reader::new(&params).finish().map_err(Rc::bare)?;
                let out = self.context_save(target, h)?;
                (None, out, auth)
            }
            Cc::ContextLoad => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let context = Context::read(&mut r).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                let handle = self.context_load(context)?;
                (Some(handle), Writer::new(), auth)
            }
            Cc::FlushContext => {
                let mut auth = self.read_auth(&mut cmd, Vec::new())?;
                let raw = cmd.params();
                let params = auth.finish(&self.stage.reset.sessions, raw)?;
                let mut r = Reader::new(&params);
                let h = r.u32().at(At::param(1))?;
                let target = ContextHandle::from_handle(h).ok_or(Fmt1::Value).at(At::param(1))?;
                r.finish().map_err(Rc::bare)?;
                self.flush_context(target)?;
                (None, Writer::new(), auth)
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
            orderly: p.orderly.is_some(),
            transient: self.stage.objects.handles_from(0),
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
            ObjectHandle::Transient(h) => {
                self.stage.objects.find(h).map(Some).ok_or(Warn::ReferenceH(slot).into())
            }
            ObjectHandle::Persistent(_) => Err(Rc::Fmt1(Fmt1::Handle, Some(At::handle(n)))),
        }
    }

    /// Checks that an entity handle names something present; returns the object it names, if
    /// it names one.
    fn resolve_entity(&self, e: EntityHandle, n: u8) -> Result<Option<Loaded>, Rc> {
        match e {
            EntityHandle::Hierarchy(_) | EntityHandle::Null | EntityHandle::Pcr(_) => Ok(None),
            EntityHandle::Transient(h) => self.resolve_object(ObjectHandle::Transient(h), n),
            EntityHandle::Persistent(h) => self.resolve_object(ObjectHandle::Persistent(h), n),
            // No NV index can be defined yet.
            EntityHandle::NvIndex(_) => Err(Rc::Fmt1(Fmt1::Handle, Some(At::handle(n)))),
        }
    }

    fn resolve_context(&self, c: ContextHandle) -> Result<ContextHandle, Rc> {
        let slot = Slot::new(0).expect("slot 0");
        let present = match c {
            ContextHandle::Transient(h) => self.stage.objects.find(h).is_some(),
            ContextHandle::Session(h) => self.stage.reset.sessions.get(h).is_some(),
        };
        if present { Ok(c) } else { Err(Warn::ReferenceH(slot).into()) }
    }

    fn name_of_object(&self, o: Option<Loaded>) -> Name2b {
        match o {
            Some(l) => self.stage.objects.get(l).name(),
            None => handle_name(crate::handle::rh::NULL),
        }
    }

    fn entity_name(&self, e: EntityHandle, loaded: Option<Loaded>) -> Name2b {
        match (e, loaded) {
            (_, Some(l)) => self.stage.objects.get(l).name(),
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
        if self.stage.objects.loaded_count() == object::MAX_LOADED_OBJECTS {
            return Err(Warn::ObjectMemory.into());
        }
        object::validate_template(&template, sensitive.data.as_slice().len(), None)
            .at(At::param(2))?;
        let name_alg = template.name_alg;
        let object =
            object::create_primary(self.secrets().seed(hierarchy), hierarchy, template, sensitive)
                .map_err(|e| match e {
                    object::Unsupported::Rsa => Rc::Fmt1(Fmt1::Type, Some(At::param(2))),
                    object::Unsupported::KeySize => Rc::Fmt1(Fmt1::KeySize, Some(At::param(1))),
                })?;
        let name = object.name();
        let (selection, pcr_digest) = self.stage.pcrs.digest(name_alg, creation_pcr.into_vec());
        let parent = handle_name(hierarchy.handle());
        let creation = CreationData {
            pcr_select: List::new(selection).expect("at most one selection, as it came in"),
            pcr_digest: Buf::from_slice(pcr_digest.as_slice()).expect("a digest"),
            locality: locality.bit(),
            parent_name_alg: crate::alg::id::NULL,
            parent_name: parent.clone(),
            parent_qualified_name: parent,
            outside_info: outside,
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
        let mut out = Writer::new();
        Tpm2b(&object.public).write(&mut out);
        Tpm2b(&creation).write(&mut out);
        out.tpm2b(creation_hash.as_slice());
        ticket.write(&mut out);
        name.write(&mut out);
        let loaded = self.stage.objects.insert(object).expect("a free slot was checked");
        Ok((loaded.handle(), out))
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
                let key = self.stage.objects.get(k);
                let PublicKind::Ecc(ecc) = &key.public.kind else {
                    return Err(match key.public.kind {
                        PublicKind::Rsa(_) => Rc::Fmt1(Fmt1::Value, Some(At::param(2))),
                        _ => Rc::Fmt1(Fmt1::Key, Some(At::handle(1))),
                    });
                };
                if input.encrypted_salt.as_slice().is_empty() {
                    return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(2))));
                }
                if !key.public.attributes.decrypt() {
                    return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(1))));
                }
                let SensitiveKind::Ecc(private) = &key.sensitive.kind else {
                    unreachable!("an ECC object holds an ECC private key");
                };
                ecc_salt(
                    key.public.name_alg,
                    private.as_slice(),
                    &ecc.unique,
                    input.encrypted_salt.as_slice(),
                )
                .ok_or(Rc::Fmt1(Fmt1::Value, Some(At::param(2))))?
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
                let o = self.stage.objects.get(l);
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
                let l = self.stage.objects.find(h).expect("resolved");
                let sequence =
                    self.stage.reset.object_sequence.checked_add(1).ok_or(Fmt0::TooManyContexts)?;
                self.stage.reset.object_sequence = sequence;
                let o = self.stage.objects.get(l);
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
                (Context { sequence, saved_handle, hierarchy: o.hierarchy, blob }, true)
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
            // janus saves no sequence objects, so no context of one can carry its HMAC.
            SavedHandle::Sequence => Err(Rc::Fmt1(Fmt1::Integrity, Some(at))),
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
                let l = self.stage.objects.find(h).ok_or(refused)?;
                self.stage.objects.remove(l);
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

/// The salt of a session salted to an ECC key: the secret is a point `QeU`, and the salt is
/// `KDFe(nameAlg, (d × QeU).x, "SECRET", QeU.x, key.x, digest bits)`. `None` for a secret that
/// is not a well-formed point on the curve.
fn ecc_salt(
    name_alg: Hash,
    private: &[u8],
    public: &EccPoint,
    secret: &[u8],
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let mut r = Reader::new(secret);
    let point = EccPoint::read(&mut r).ok()?;
    r.finish().ok()?;
    let peer = EccPublicKey::from_coordinates(point.x.as_slice(), point.y.as_slice())?;
    let key = EccPrivate::from_bytes(private).expect("a stored ECC key is a valid scalar");
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
