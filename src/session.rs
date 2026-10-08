// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sessions, and the authorization of a command.
//!
//! A command handler that acts on an entity needing authorization takes an [`Authorized`] for
//! it, and only [`Authorization::authorize`] makes one, after the session for that handle has
//! been checked. A handler cannot forget the check because it cannot get the entity without it.
//!
//! An [`Authorization`] lives for one command. It is read from the command's authorization
//! area against the session table, then walks the reference's order: each handle's session is
//! checked as the handler authorizes it, then the sessions that authorize nothing (parameter
//! encryption), then the first parameter is decrypted. After the command runs, it encrypts the
//! first response parameter, rolls every session's nonce and computes the response HMACs.

use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::Platform;
use crate::alg::{Hash, MAX_DIGEST};
use crate::cc::Attributes;
use crate::crypto;
use crate::handle::{AuthSessionHandle, handle_type, ht};
use crate::marshal::{Marshal, Unmarshal};
use crate::rc::{At, Fmt0, Fmt1, Index, Rc, Slot, Warn};
use crate::types::{AesDef, Name2b, Secret, SymDef};
use crate::wire::{Blame as _, Buf, Bytes, Reader, Writer};

/// At most three sessions per command (`MAX_SESSION_NUM`).
const MAX_SESSIONS: usize = 3;

/// The smallest session on the wire: a handle, two empty TPM2Bs and the attributes.
const MIN_SESSION_SIZE: u32 = 9;

/// An authorization value, stored with trailing zeros removed as the TPM requires. It is never
/// printed, never cloned, compared only in constant time and wiped when dropped.
pub struct AuthValue(Buf<MAX_DIGEST>);

impl AuthValue {
    pub const fn empty() -> AuthValue {
        AuthValue(Buf::empty())
    }

    pub fn from_wire(b: Bytes<'_, MAX_DIGEST>) -> AuthValue {
        AuthValue::from_slice(b.get())
    }

    /// From bytes no longer than a digest, trailing zeros removed.
    pub fn from_slice(b: &[u8]) -> AuthValue {
        let mut buf = Buf::from_slice(b).expect("an authValue is at most a digest");
        buf.trim_trailing_zeros();
        AuthValue(buf)
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_slice().is_empty()
    }

    /// The value as key material for an HMAC or KDF. Never compared through this.
    pub fn key_material(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Whether `presented`, with its own trailing zeros removed, is this value.
    fn matches(&self, presented: &[u8]) -> bool {
        let mut end = presented.len();
        while end > 0 && presented[end - 1] == 0 {
            end -= 1;
        }
        let presented = &presented[..end];
        // The lengths are compared in the open: an authValue's length is not secret in the
        // reference either, and comparing contents of different lengths is meaningless.
        presented.len() == self.0.as_slice().len() && bool::from(presented.ct_eq(self.0.as_slice()))
    }
}

impl Drop for AuthValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

wire_bits! {
    /// `TPMA_SESSION`.
    pub struct SessionAttributes(u8) reserved 0x18; {
        continue_session = 0,
        audit_exclusive = 1,
        audit_reset = 2,
        decrypt = 5,
        encrypt = 6,
        audit = 7,
    }
}

wire_struct! {
    /// What a session needs that HMAC and policy sessions share.
    pub struct Core {
        pub auth_hash: Hash,
        pub nonce_tpm: Buf<MAX_DIGEST>,
        pub symmetric: SymDef,
        /// Empty for an unbound, unsalted session.
        pub session_key: Secret<MAX_DIGEST>,
        /// The use of this session is subject to dictionary-attack lockout: it was bound to a
        /// protected entity.
        pub da_bound: bool,
        /// ...and that entity was the lockout hierarchy.
        pub lockout_bound: bool,
    }
}

wire_struct! {
    /// An HMAC session (`TPM_SE_HMAC`).
    pub struct HmacSession {
        pub core: Core,
        /// `H(name || authValue)` of the entity the session was bound to.
        pub bound: Option<[u8; 32]>,
    }
}

wire_struct! {
    /// A policy or trial session (`TPM_SE_POLICY`, `TPM_SE_TRIAL`).
    pub struct PolicySession {
        pub core: Core,
        pub trial: bool,
        pub digest: [u8; 32],
        /// `TPM2_PolicyAuthValue` ran: the authorized entity's authValue joins the HMAC key.
        pub auth_value_needed: bool,
        /// `TPM2_PolicyPassword` ran: the HMAC field carries the authValue in the clear.
        pub password_needed: bool,
        /// `TPM2_PolicyCommandCode`.
        pub command_code: Option<u32>,
        /// `TPM2_PolicyPCR`: the PCR update counter the policy was computed against.
        pub pcr_counter: Option<u32>,
    }
}

wire_union! {
    /// A session, tagged by the handle type it lives under. The tag is also its saved form's
    /// selector, so a saved context cannot come back as the other kind.
    pub enum Session: u8 [Fmt1::Value] {
        Hmac = ht::HMAC_SESSION => HmacSession,
        Policy = ht::POLICY_SESSION => PolicySession,
    }
}

impl PolicySession {
    /// `policyDigest := H(policyDigest || parts...)`, the update every policy command makes.
    pub fn extend(&mut self, parts: &[&[u8]]) {
        let mut all: Vec<&[u8]> = vec![&self.digest];
        all.extend_from_slice(parts);
        let d = self.core.auth_hash.digest(&all);
        self.digest.copy_from_slice(d.as_slice());
    }

    /// Back to the state `TPM2_StartAuthSession` left it in, but for its nonces
    /// (`SessionResetPolicyData`).
    pub fn restart(&mut self) {
        self.digest = [0; 32];
        self.auth_value_needed = false;
        self.password_needed = false;
        self.command_code = None;
        self.pcr_counter = None;
    }
}

impl Session {
    pub fn core(&self) -> &Core {
        match self {
            Session::Hmac(s) => &s.core,
            Session::Policy(s) => &s.core,
        }
    }

    fn core_mut(&mut self) -> &mut Core {
        match self {
            Session::Hmac(s) => &mut s.core,
            Session::Policy(s) => &mut s.core,
        }
    }

    fn handle_type(&self) -> u8 {
        self.selector()
    }
}

/// Active sessions, loaded or saved (`MAX_ACTIVE_SESSIONS`).
pub const MAX_ACTIVE_SESSIONS: usize = 64;
/// Sessions in memory at once (`MAX_LOADED_SESSIONS`).
pub const MAX_LOADED_SESSIONS: usize = 3;
/// How far the newest saved session's sequence may run ahead of the oldest
/// (`TPM_PT_CONTEXT_GAP_MAX`).
pub const CONTEXT_GAP_MAX: u64 = 0xFFFF;

enum SessionSlot {
    Free,
    Loaded(Box<Session>),
    /// Saved by `TPM2_ContextSave` with this sequence; only a context carrying the same
    /// sequence loads it back.
    Saved {
        sequence: u64,
        kind: u8,
    },
}

/// The session handle space. A session's handle is its slot index with its type in the top
/// byte; the slot stays assigned while the session is saved, so a context can only come back
/// to the handle it left.
pub struct SessionTable {
    slots: Vec<SessionSlot>,
    /// The sequence the next saved session gets (`contextCounter`).
    next_sequence: u64,
}

impl Default for SessionTable {
    fn default() -> Self {
        SessionTable {
            slots: (0..MAX_ACTIVE_SESSIONS).map(|_| SessionSlot::Free).collect(),
            next_sequence: 1,
        }
    }
}

fn slot_index(handle: u32) -> Option<usize> {
    let i = (handle & 0x00FF_FFFF) as usize;
    (i < MAX_ACTIVE_SESSIONS).then_some(i)
}

impl SessionTable {
    fn loaded(&self) -> usize {
        self.slots.iter().filter(|s| matches!(s, SessionSlot::Loaded(_))).count()
    }

    /// The loaded session `handle` names, if it names one of its own type.
    pub fn get(&self, handle: u32) -> Option<&Session> {
        match &self.slots[slot_index(handle)?] {
            SessionSlot::Loaded(s) if s.handle_type() == handle_type(handle) => Some(s),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, handle: u32) -> Option<&mut Session> {
        match &mut self.slots[slot_index(handle)?] {
            SessionSlot::Loaded(s) if s.handle_type() == handle_type(handle) => Some(s),
            _ => None,
        }
    }

    /// Whether `handle` names a session that is loaded or saved.
    pub fn is_active(&self, handle: u32) -> bool {
        slot_index(handle).is_some_and(|i| match &self.slots[i] {
            SessionSlot::Free => false,
            SessionSlot::Loaded(s) => s.handle_type() == handle_type(handle),
            SessionSlot::Saved { kind, .. } => *kind == handle_type(handle),
        })
    }

    /// Starts `session` in the lowest free slot and returns its handle.
    pub fn create(&mut self, session: Session) -> Result<u32, Rc> {
        if self.loaded() >= MAX_LOADED_SESSIONS {
            return Err(Warn::SessionMemory.into());
        }
        let Some(i) = self.slots.iter().position(|s| matches!(s, SessionSlot::Free)) else {
            return Err(Warn::SessionHandles.into());
        };
        let handle = (u32::from(session.handle_type()) << 24) | i as u32;
        self.slots[i] = SessionSlot::Loaded(Box::new(session));
        Ok(handle)
    }

    /// Flushes a loaded or saved session; `false` when `handle` names neither.
    pub fn flush(&mut self, handle: u32) -> bool {
        if !self.is_active(handle) {
            return false;
        }
        let i = slot_index(handle).expect("an active handle has a slot");
        self.slots[i] = SessionSlot::Free;
        true
    }

    /// Takes a loaded session out of memory for `TPM2_ContextSave`, leaving its slot saved under
    /// a new sequence, which it returns with the session.
    pub fn save(&mut self, handle: u32) -> Result<(u64, Box<Session>), Rc> {
        let i = slot_index(handle).ok_or(Warn::ReferenceH(Slot::new(0).expect("slot 0")))?;
        if !matches!(&self.slots[i], SessionSlot::Loaded(s) if s.handle_type() == handle_type(handle))
        {
            return Err(Warn::ReferenceH(Slot::new(0).expect("slot 0")).into());
        }
        let sequence = self.next_sequence;
        let oldest = self
            .slots
            .iter()
            .filter_map(|s| match s {
                SessionSlot::Saved { sequence, .. } => Some(*sequence),
                _ => None,
            })
            .min();
        if oldest.is_some_and(|o| sequence - o >= CONTEXT_GAP_MAX) {
            return Err(Warn::ContextGap.into());
        }
        self.next_sequence = sequence.checked_add(1).ok_or(Fmt0::TooManyContexts)?;
        let kind = handle_type(handle);
        let SessionSlot::Loaded(s) =
            std::mem::replace(&mut self.slots[i], SessionSlot::Saved { sequence, kind })
        else {
            unreachable!("checked above");
        };
        Ok((sequence, s))
    }

    /// Puts a saved session back. The slot must be saved under exactly `sequence`
    /// (`TPM_RC_HANDLE`), and there must be room (`TPM_RC_SESSION_MEMORY`).
    pub fn restore(&mut self, handle: u32, sequence: u64, session: Session) -> Result<(), Rc> {
        let i = slot_index(handle).ok_or(Rc::Fmt1(Fmt1::Handle, Some(At::param(1))))?;
        match &self.slots[i] {
            SessionSlot::Saved { sequence: s, kind }
                if *s == sequence
                    && *kind == handle_type(handle)
                    && *kind == session.handle_type() => {}
            _ => return Err(Rc::Fmt1(Fmt1::Handle, Some(At::param(1)))),
        }
        if self.loaded() >= MAX_LOADED_SESSIONS {
            return Err(Warn::SessionMemory.into());
        }
        self.slots[i] = SessionSlot::Loaded(Box::new(session));
        Ok(())
    }

    /// `_TPM_Init`: what was in memory is gone; saved sessions keep their slots until a TPM
    /// Reset replaces the whole table.
    pub fn drop_loaded(&mut self) {
        for s in &mut self.slots {
            if matches!(s, SessionSlot::Loaded(_)) {
                *s = SessionSlot::Free;
            }
        }
    }

    /// The handles of loaded (`saved == false`) or saved sessions at or above `from`.
    pub fn handles_from(&self, from: u32, saved: bool) -> Vec<u32> {
        let mut out: Vec<u32> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                SessionSlot::Loaded(s) if !saved => {
                    Some((u32::from(s.handle_type()) << 24) | i as u32)
                }
                SessionSlot::Saved { kind, .. } if saved => {
                    Some((u32::from(*kind) << 24) | i as u32)
                }
                _ => None,
            })
            .filter(|h| *h >= from)
            .collect();
        out.sort_unstable();
        out
    }
}

/// An entity a session can authorize.
pub trait Entity: Copy {}

/// What the session check needs to know about the entity a handle names.
pub struct EntityAuth<'v> {
    pub name: &'v [u8],
    pub value: &'v AuthValue,
    /// The entity's `authPolicy`; empty when it has none.
    pub policy: &'v [u8],
    pub da: Da,
    /// The authValue may be used for this role (`IsAuthValueAvailable`): an object needs
    /// `userWithAuth` for the USER role.
    pub value_available: bool,
}

/// How a failed authorization of an entity counts toward dictionary-attack lockout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Da {
    /// Every permanent handle but lockout, every PCR, and objects with `noDA`.
    Exempt,
    Protected,
    /// The lockout hierarchy: a failure disables it until recovery.
    Lockout,
}

/// Proof that the session for `entity` was checked. Only [`Authorization::authorize`] makes one.
pub struct Authorized<E> {
    entity: E,
}

impl<E: Copy> Authorized<E> {
    pub fn entity(&self) -> E {
        self.entity
    }
}

/// The dictionary-attack state the authorization check reads and updates (the reference's
/// `DA.c`). The counters and parameters survive `_TPM_Init`, as the reference keeps them in NV;
/// the two timers restart at every Startup.
pub struct Lockout {
    /// Failed authorizations of protected entities not yet healed (`failedTries`).
    failed_tries: u32,
    /// The failures at which protected entities lock out (`maxTries`).
    max_tries: u32,
    /// Seconds per healed failure (`recoveryTime`); 0 turns the counter off.
    recovery_time: u32,
    /// Seconds after a failed lockout authorization before it may be tried again
    /// (`lockoutRecovery`); 0 means only at the next Startup.
    lockout_recovery: u32,
    /// The lockout hierarchy's authorization may be used (`lockOutAuthEnabled`).
    lockout_auth_enabled: bool,
    /// `Time`, in milliseconds since `_TPM_Init`, as of the command being executed.
    now: u64,
    /// When the healing of `failed_tries` last advanced or a failure restarted it.
    self_heal_timer: u64,
    /// When the lockout hierarchy's authorization last failed.
    lockout_timer: u64,
}

impl Lockout {
    /// The values a new TPM is manufactured with (`DAPreInstall_Init`).
    pub fn manufactured() -> Lockout {
        Lockout {
            failed_tries: 0,
            max_tries: 3,
            recovery_time: 1000,
            lockout_recovery: 1000,
            lockout_auth_enabled: true,
            now: 0,
            self_heal_timer: 0,
            lockout_timer: 0,
        }
    }

    /// `DAStartup`, in the reference's build without `USE_DA_USED` or an accumulating
    /// self-heal timer (the guests' TPM, libtpms, never answers the first protected
    /// authorization after a Startup with `TPM_RC_RETRY`): the timers restart; a lockout that
    /// recovers only at Startup recovers; and a Startup after no orderly shutdown counts as a
    /// failure, since one may have gone unrecorded.
    pub fn startup(&mut self, orderly: bool) {
        self.now = 0;
        self.self_heal_timer = 0;
        self.lockout_timer = 0;
        if self.lockout_recovery == 0 {
            self.lockout_auth_enabled = true;
        }
        if self.recovery_time != 0 && self.failed_tries < self.max_tries && !orderly {
            self.failed_tries += 1;
        }
    }

    /// `DASelfHeal` at `time`, `Time` in milliseconds: one failure heals per `recovery_time`
    /// seconds since the timer, and the lockout hierarchy recovers `lockout_recovery` seconds
    /// after its last failure.
    pub fn self_heal(&mut self, time: u64) {
        self.now = time;
        if self.failed_tries != 0 {
            if self.recovery_time == 0 {
                self.failed_tries = 0;
            } else {
                let healed = time.saturating_sub(self.self_heal_timer)
                    / 1000
                    / u64::from(self.recovery_time);
                self.failed_tries =
                    self.failed_tries.saturating_sub(u32::try_from(healed).unwrap_or(u32::MAX));
                self.self_heal_timer = self
                    .self_heal_timer
                    .saturating_add(healed.saturating_mul(u64::from(self.recovery_time)) * 1000);
            }
        }
        if !self.lockout_auth_enabled
            && self.lockout_recovery != 0
            && time.saturating_sub(self.lockout_timer) / 1000 >= u64::from(self.lockout_recovery)
        {
            self.lockout_auth_enabled = true;
        }
    }

    /// `CheckLockedOut`: the lockout hierarchy (`lockout_auth`) while its use is disabled, any
    /// other protected entity while the failures reach the limit.
    fn locked_out(&self, lockout_auth: bool) -> bool {
        if lockout_auth { !self.lockout_auth_enabled } else { self.failed_tries >= self.max_tries }
    }

    /// The failures have reached the limit (`TPMA_PERMANENT.inLockout`).
    pub fn in_lockout(&self) -> bool {
        self.locked_out(false)
    }

    /// The counter of `IncrementLockout` and `DARegisterFailure`: a failed lockout
    /// authorization disables it, any other counts a failure; either restarts its timer.
    fn register_failure(&mut self, lockout_auth: bool) {
        if lockout_auth {
            self.lockout_auth_enabled = false;
            self.lockout_timer = self.now;
        } else {
            if self.recovery_time != 0 {
                self.failed_tries = self.failed_tries.saturating_add(1);
            }
            self.self_heal_timer = self.now;
        }
    }

    /// `TPM2_DictionaryAttackLockReset`.
    pub fn reset(&mut self) {
        self.failed_tries = 0;
    }

    /// `TPM2_DictionaryAttackParameters`.
    pub fn set_parameters(&mut self, max_tries: u32, recovery_time: u32, lockout_recovery: u32) {
        self.max_tries = max_tries;
        self.recovery_time = recovery_time;
        self.lockout_recovery = lockout_recovery;
    }

    /// `TPM_PT_LOCKOUT_COUNTER`, `TPM_PT_MAX_AUTH_FAIL`, `TPM_PT_LOCKOUT_INTERVAL` and
    /// `TPM_PT_LOCKOUT_RECOVERY`.
    pub fn properties(&self) -> [u32; 4] {
        [self.failed_tries, self.max_tries, self.recovery_time, self.lockout_recovery]
    }
}

/// Which session a command's authorization area names.
#[derive(Clone, Copy)]
enum SessionRef {
    Password,
    Loaded(u32),
}

struct Entry {
    session: SessionRef,
    nonce_caller: Buf<MAX_DIGEST>,
    attributes: SessionAttributes,
    hmac: Secret<MAX_DIGEST>,
    /// The authorized entity's authValue, for the parameter-encryption key and, when
    /// `include_auth`, the HMAC key. Empty for a session that authorizes nothing.
    auth_value: Zeroizing<Vec<u8>>,
    include_auth: bool,
}

/// One command's authorization area, through the command.
pub struct Authorization {
    cc: u32,
    entries: Vec<Entry>,
    decrypt: Option<usize>,
    encrypt: Option<usize>,
    /// Handles needing authorization; their sessions come first.
    auth_handles: usize,
    /// How many of those [`Authorization::authorize`] has checked.
    checked: usize,
    /// The names of every handle in the command, for the cpHash.
    names: Vec<Name2b>,
}

fn at_session(i: usize) -> At {
    At::Session(Index::new(i as u8 + 1).expect("at most three sessions"))
}

impl Authorization {
    /// Reads a command's authorization area (`None` for `TPM_ST_NO_SESSIONS`), in the
    /// reference's order (`RetrieveSessionData`, then the binding in `ParseSessionBuffer`).
    pub fn read(
        area: Option<&mut Reader<'_>>,
        sessions: &SessionTable,
        cc: u32,
        attributes: Attributes,
        names: Vec<Name2b>,
    ) -> Result<Authorization, Rc> {
        let auth_handles = usize::from(attributes.auth_handles);
        let mut entries = Vec::new();
        let mut decrypt = None;
        let mut encrypt = None;
        if let Some(r) = area {
            let size = r.u32().map_err(Rc::bare)?;
            if size < MIN_SESSION_SIZE || size as usize > r.remaining() {
                return Err(Rc::bare(Fmt1::Size));
            }
            if attributes.no_sessions {
                return Err(Fmt0::AuthContext.into());
            }
            let mut area = r.split(size as usize).map_err(Rc::bare)?;
            while !area.is_empty() {
                let i = entries.len();
                let at = At::Session(Index::new(i as u8 + 1).expect("at most four sessions"));
                if i == MAX_SESSIONS {
                    return Err(Rc::Fmt1(Fmt1::Size, Some(at)));
                }
                let handle = area.u32().at(at)?;
                let handle = AuthSessionHandle::from_handle(handle).ok_or(Fmt1::Value).at(at)?;
                let nonce_caller = Buf::read(&mut area).at(at)?;
                let attrs = SessionAttributes::read(&mut area).at(at)?;
                let hmac = Secret::read(&mut area).at(at)?;
                let session = match handle {
                    AuthSessionHandle::Password => {
                        if attrs.encrypt()
                            || attrs.decrypt()
                            || attrs.audit()
                            || attrs.audit_exclusive()
                            || attrs.audit_reset()
                        {
                            return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                        }
                        if !nonce_caller.as_slice().is_empty() {
                            return Err(Rc::Fmt1(Fmt1::Nonce, Some(at)));
                        }
                        SessionRef::Password
                    }
                    AuthSessionHandle::Hmac(h) | AuthSessionHandle::Policy(h) => {
                        let Some(session) = sessions.get(h) else {
                            let slot = Slot::new(i as u8).expect("at most three sessions");
                            return Err(Warn::ReferenceS(slot).into());
                        };
                        if entries
                            .iter()
                            .any(|e: &Entry| matches!(e.session, SessionRef::Loaded(x) if x == h))
                        {
                            return Err(Rc::Fmt1(Fmt1::Handle, Some(at)));
                        }
                        if attrs.decrypt() {
                            if !attributes.decrypt || decrypt.is_some() {
                                return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                            }
                            if session.core().symmetric == SymDef::Null(()) {
                                return Err(Rc::Fmt1(Fmt1::Symmetric, Some(at)));
                            }
                            decrypt = Some(i);
                        }
                        if attrs.encrypt() {
                            if !attributes.encrypt || encrypt.is_some() {
                                return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                            }
                            if session.core().symmetric == SymDef::Null(()) {
                                return Err(Rc::Fmt1(Fmt1::Symmetric, Some(at)));
                            }
                            encrypt = Some(i);
                        }
                        // Audit sessions are not implemented.
                        if attrs.audit() {
                            return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                        }
                        SessionRef::Loaded(h)
                    }
                };
                entries.push(Entry {
                    session,
                    nonce_caller,
                    attributes: attrs,
                    hmac,
                    auth_value: Zeroizing::new(Vec::new()),
                    include_auth: false,
                });
            }
        }
        if auth_handles > entries.len() {
            return Err(Fmt0::AuthMissing.into());
        }
        for (i, e) in entries.iter().enumerate() {
            let at = at_session(i);
            match e.session {
                SessionRef::Password if i >= auth_handles => {
                    return Err(Rc::Fmt1(Fmt1::Handle, Some(at)));
                }
                SessionRef::Loaded(h) => {
                    if let Some(Session::Policy(p)) = sessions.get(h)
                        && p.trial
                    {
                        return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                    }
                }
                SessionRef::Password => {}
            }
        }
        Ok(Authorization { cc, entries, decrypt, encrypt, auth_handles, checked: 0, names })
    }

    fn cp_hash(&self, hash: Hash, params: &[u8]) -> Vec<u8> {
        let cc = self.cc.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&cc];
        parts.extend(self.names.iter().map(|n| n.as_slice()));
        parts.push(params);
        hash.digest(&parts).as_slice().to_vec()
    }

    /// The nonces of the decrypt and encrypt sessions, which the first authorization session's
    /// HMAC also covers when they are other sessions (`ComputeCommandHMAC`).
    fn extra_nonces(&self, i: usize, sessions: &SessionTable) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if i != 0 || self.auth_handles == 0 {
            return out;
        }
        let nonce_of = |j: usize| match self.entries[j].session {
            SessionRef::Loaded(h) => {
                sessions.get(h).expect("read() found it").core().nonce_tpm.as_slice().to_vec()
            }
            SessionRef::Password => unreachable!("a password session cannot encrypt"),
        };
        if let Some(d) = self.decrypt
            && d != i
        {
            out.push(nonce_of(d));
        }
        if let Some(e) = self.encrypt
            && e != i
            && Some(e) != self.decrypt
        {
            out.push(nonce_of(e));
        }
        out
    }

    /// The command HMAC session `i` must carry, or `None` when its key is empty and so is its
    /// HMAC field (a NULL HMAC, which the reference allows).
    fn command_hmac(
        &self,
        i: usize,
        sessions: &SessionTable,
        params: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let e = &self.entries[i];
        let SessionRef::Loaded(h) = e.session else { unreachable!("HMAC of a password") };
        let core = sessions.get(h).expect("read() found it").core();
        let mut key = Zeroizing::new(core.session_key.as_slice().to_vec());
        if e.include_auth {
            key.extend_from_slice(&e.auth_value);
        }
        if key.is_empty() && e.hmac.as_slice().is_empty() {
            return None;
        }
        let cp = self.cp_hash(core.auth_hash, params);
        let extra = self.extra_nonces(i, sessions);
        let attrs = [e.attributes.bits()];
        let mut parts: Vec<&[u8]> = vec![&cp, e.nonce_caller.as_slice(), core.nonce_tpm.as_slice()];
        parts.extend(extra.iter().map(Vec::as_slice));
        parts.push(&attrs);
        Some(crypto::hmac(core.auth_hash, &key, &parts))
    }

    fn check_hmac(&self, i: usize, sessions: &SessionTable, params: &[u8]) -> bool {
        let e = &self.entries[i];
        match self.command_hmac(i, sessions, params) {
            None => true,
            Some(expected) => {
                expected.len() == e.hmac.as_slice().len()
                    && bool::from(expected.ct_eq(e.hmac.as_slice()))
            }
        }
    }

    /// Checks the session for the next handle needing authorization (`CheckAuthSession`),
    /// against `params`, the command's parameter bytes as they arrived.
    pub fn authorize<E: Entity>(
        &mut self,
        sessions: &SessionTable,
        params: &[u8],
        entity: E,
        auth: &EntityAuth<'_>,
        lockout: &mut Lockout,
        pcr_counter: u32,
    ) -> Result<Authorized<E>, Rc> {
        let i = self.checked;
        assert!(i < self.auth_handles, "authorize() called for more handles than the command has");
        self.checked += 1;
        let at = at_session(i);
        let locked_out = |lockout: &Lockout| match auth.da {
            Da::Exempt => false,
            Da::Protected => lockout.locked_out(false),
            Da::Lockout => lockout.locked_out(true),
        };
        match self.entries[i].session {
            SessionRef::Password => {
                if locked_out(lockout) {
                    return Err(Warn::Lockout.into());
                }
                if !auth.value_available {
                    return Err(Fmt0::AuthUnavailable.into());
                }
                let presented = self.entries[i].hmac.as_slice().to_vec();
                if auth.value.matches(&presented) {
                    self.entries[i].auth_value = Zeroizing::new(auth.value.key_material().to_vec());
                    return Ok(Authorized { entity });
                }
                // IncrementLockout for a password: only the entity's own protection counts.
                if auth.da == Da::Exempt {
                    return Err(Rc::Fmt1(Fmt1::BadAuth, Some(at)));
                }
                lockout.register_failure(auth.da == Da::Lockout);
                Err(Rc::Fmt1(Fmt1::AuthFail, Some(at)))
            }
            SessionRef::Loaded(h) => {
                let session = sessions.get(h).expect("read() found it");
                let core = session.core();
                // A session bound to a protected entity is refused while that entity's kind is
                // locked out, whatever it authorizes now (`ExecCommand`'s session loop).
                if core.da_bound && lockout.locked_out(core.lockout_bound) {
                    return Err(Warn::Lockout.into());
                }
                // IncrementLockout for a session: one bound to lockout counts as lockout; one
                // bound to no protected entity counts only if the authValue was in the HMAC of
                // a protected entity.
                let (da_bound, lockout_bound) = (core.da_bound, core.lockout_bound);
                let fail = |lockout: &mut Lockout, include_auth: bool| -> Rc {
                    let exempt = !lockout_bound && auth.da == Da::Exempt;
                    if !da_bound && (exempt || !include_auth) {
                        return Rc::Fmt1(Fmt1::BadAuth, Some(at));
                    }
                    lockout.register_failure(lockout_bound || auth.da == Da::Lockout);
                    Rc::Fmt1(Fmt1::AuthFail, Some(at))
                };
                self.entries[i].auth_value = Zeroizing::new(auth.value.key_material().to_vec());
                match session {
                    Session::Hmac(s) => {
                        let bound = s.bound.is_some_and(|b| b == bind_id(auth.name, auth.value));
                        self.entries[i].include_auth = !bound;
                        if !bound && locked_out(lockout) {
                            return Err(Warn::Lockout.into());
                        }
                        if !auth.value_available {
                            return Err(Fmt0::AuthUnavailable.into());
                        }
                        if self.check_hmac(i, sessions, params) {
                            Ok(Authorized { entity })
                        } else {
                            Err(fail(lockout, !bound))
                        }
                    }
                    Session::Policy(p) => {
                        self.entries[i].include_auth = p.auth_value_needed || p.password_needed;
                        if self.entries[i].include_auth && locked_out(lockout) {
                            return Err(Warn::Lockout.into());
                        }
                        if auth.policy.is_empty() {
                            return Err(Fmt0::AuthUnavailable.into());
                        }
                        // CheckPolicyAuthSession, in its order.
                        if p.pcr_counter.is_some_and(|c| c != pcr_counter) {
                            return Err(Fmt0::PcrChanged.into());
                        }
                        if !bool::from(p.digest[..].ct_eq(auth.policy)) {
                            return Err(Rc::Fmt1(Fmt1::PolicyFail, Some(at)));
                        }
                        if p.command_code.is_some_and(|c| c != self.cc) {
                            return Err(Rc::Fmt1(Fmt1::PolicyCc, Some(at)));
                        }
                        if p.password_needed {
                            let presented = self.entries[i].hmac.as_slice().to_vec();
                            return if auth.value.matches(&presented) {
                                Ok(Authorized { entity })
                            } else {
                                Err(fail(lockout, true))
                            };
                        }
                        let include_auth = self.entries[i].include_auth;
                        if self.check_hmac(i, sessions, params) {
                            Ok(Authorized { entity })
                        } else {
                            Err(fail(lockout, include_auth))
                        }
                    }
                }
            }
        }
    }

    /// After every handle is authorized: checks the sessions that authorize nothing, then
    /// decrypts the first parameter if a session asked for it. Returns the parameters to parse.
    ///
    /// Such a session bound to a protected entity is refused while that entity's kind is
    /// locked out, and its failed HMAC counts as a failure of that kind; one bound to nothing
    /// protected fails with `TPM_RC_BAD_AUTH` and counts nothing.
    pub fn finish(
        &mut self,
        sessions: &SessionTable,
        params: &[u8],
        lockout: &mut Lockout,
    ) -> Result<Vec<u8>, Rc> {
        assert_eq!(self.checked, self.auth_handles, "a handle's session was never checked");
        for i in self.auth_handles..self.entries.len() {
            let at = at_session(i);
            let e = &self.entries[i];
            let SessionRef::Loaded(h) = e.session else { unreachable!("read() refused it") };
            let core = sessions.get(h).expect("read() found it").core();
            if core.da_bound && lockout.locked_out(core.lockout_bound) {
                return Err(Warn::Lockout.into());
            }
            if !e.attributes.encrypt() && !e.attributes.decrypt() && !e.attributes.audit() {
                return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
            }
            if !self.check_hmac(i, sessions, params) {
                if !core.da_bound {
                    return Err(Rc::Fmt1(Fmt1::BadAuth, Some(at)));
                }
                lockout.register_failure(core.lockout_bound);
                return Err(Rc::Fmt1(Fmt1::AuthFail, Some(at)));
            }
        }
        let mut params = params.to_vec();
        if let Some(d) = self.decrypt {
            let at = at_session(d);
            let e = &self.entries[d];
            let SessionRef::Loaded(h) = e.session else { unreachable!() };
            let core = sessions.get(h).expect("read() found it").core();
            if params.len() < 2 {
                return Err(Rc::Fmt1(Fmt1::Insufficient, Some(at)));
            }
            let n = usize::from(u16::from_be_bytes([params[0], params[1]]));
            if n > params.len() - 2 {
                return Err(Rc::Fmt1(Fmt1::Size, Some(at)));
            }
            let SymDef::Aes(aes) = core.symmetric else { unreachable!("read() refused NULL") };
            parameter_cipher(core, aes, &e.auth_value, &e.nonce_caller, Direction::Command)
                .apply(&mut params[2..2 + n]);
        }
        Ok(params)
    }

    /// Replaces the authValue a session's response HMAC uses, for a command that changed it
    /// (`TPM2_HierarchyChangeAuth` answers under the new value).
    pub fn set_response_auth(&mut self, i: usize, value: &AuthValue) {
        self.entries[i].auth_value = Zeroizing::new(value.key_material().to_vec());
    }

    /// Builds the response's parameter area and authorization area: rolls every session's
    /// nonce, encrypts the first parameter if asked, computes the response HMACs, and flushes
    /// the sessions that did not ask to continue.
    pub fn respond(
        self,
        sessions: &mut SessionTable,
        platform: &mut impl Platform,
        mut params: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>) {
        for e in &self.entries {
            if let SessionRef::Loaded(h) = e.session {
                let core =
                    sessions.get_mut(h).expect("a command's sessions stay loaded").core_mut();
                let mut nonce = vec![0u8; core.nonce_tpm.as_slice().len()];
                platform.fill_random(&mut nonce);
                core.nonce_tpm = Buf::from_slice(&nonce).expect("same size as before");
            }
        }
        if let Some(i) = self.encrypt {
            let e = &self.entries[i];
            let SessionRef::Loaded(h) = e.session else { unreachable!() };
            let core = sessions.get(h).expect("still loaded").core();
            let SymDef::Aes(aes) = core.symmetric else { unreachable!("read() refused NULL") };
            assert!(params.len() >= 2, "an encrypted response parameter is a TPM2B");
            let n = usize::from(u16::from_be_bytes([params[0], params[1]]));
            parameter_cipher(core, aes, &e.auth_value, &e.nonce_caller, Direction::Response)
                .apply(&mut params[2..2 + n]);
        }
        let mut area = Writer::new();
        let mut flush = Vec::new();
        for e in &self.entries {
            match e.session {
                SessionRef::Password => {
                    area.tpm2b(&[]);
                    area.u8(1);
                    area.tpm2b(&[]);
                }
                SessionRef::Loaded(h) => {
                    let session = sessions.get(h).expect("still loaded");
                    let core = session.core();
                    let mut key = Zeroizing::new(core.session_key.as_slice().to_vec());
                    if e.include_auth {
                        key.extend_from_slice(&e.auth_value);
                    }
                    let password = matches!(session, Session::Policy(p) if p.password_needed);
                    let hmac = if password || (key.is_empty() && e.hmac.as_slice().is_empty()) {
                        Zeroizing::new(Vec::new())
                    } else {
                        let rp = core.auth_hash.digest(&[
                            &0u32.to_be_bytes(),
                            &self.cc.to_be_bytes(),
                            &params,
                        ]);
                        crypto::hmac(
                            core.auth_hash,
                            &key,
                            &[
                                rp.as_slice(),
                                core.nonce_tpm.as_slice(),
                                e.nonce_caller.as_slice(),
                                &[e.attributes.bits()],
                            ],
                        )
                    };
                    area.tpm2b(core.nonce_tpm.as_slice());
                    area.u8(e.attributes.bits());
                    area.tpm2b(&hmac);
                    if !e.attributes.continue_session() {
                        flush.push(h);
                    } else if let Some(Session::Policy(p)) = sessions.get_mut(h) {
                        // A policy session that authorized a command starts over
                        // (`UpdateInternalSession`).
                        p.restart();
                    }
                }
            }
        }
        for h in flush {
            sessions.flush(h);
        }
        (params, area.into_vec())
    }
}

/// The identity a bound session remembers its entity by.
pub fn bind_id(name: &[u8], value: &AuthValue) -> [u8; 32] {
    let d = Hash::Sha256.digest(&[name, value.key_material()]);
    d.as_slice().try_into().expect("SHA-256")
}

enum Direction {
    Command,
    Response,
}

struct ParameterCipher {
    key: Zeroizing<[u8; 16]>,
    iv: [u8; 16],
    direction: Direction,
}

impl ParameterCipher {
    fn apply(&self, data: &mut [u8]) {
        match self.direction {
            Direction::Command => crypto::aes128_cfb_decrypt(&self.key, &self.iv, data),
            Direction::Response => crypto::aes128_cfb_encrypt(&self.key, &self.iv, data),
        }
    }
}

/// The AES-CFB key and IV for parameter encryption: `KDFa(hash, sessionKey || authValue,
/// "CFB", nonceNewer, nonceOlder, bits)`, the caller's nonce being the newer one in a command
/// and the TPM's in a response.
fn parameter_cipher(
    core: &Core,
    aes: AesDef,
    auth_value: &[u8],
    nonce_caller: &Buf<MAX_DIGEST>,
    direction: Direction,
) -> ParameterCipher {
    let _ = aes; // AES-128 in CFB mode is the only definition `AesDef` can hold.
    let mut key_material = Zeroizing::new(core.session_key.as_slice().to_vec());
    key_material.extend_from_slice(auth_value);
    let (newer, older) = match direction {
        Direction::Command => (nonce_caller.as_slice(), core.nonce_tpm.as_slice()),
        Direction::Response => (core.nonce_tpm.as_slice(), nonce_caller.as_slice()),
    };
    let bits = crypto::kdfa(core.auth_hash, &key_material, b"CFB", newer, older, 256);
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&bits[..16]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&bits[16..32]);
    ParameterCipher { key, iv, direction }
}

/// `TPM_SE`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Hmac,
    Policy,
    Trial,
}

impl SessionType {
    pub fn read(r: &mut Reader<'_>) -> Result<SessionType, Fmt1> {
        match r.u8()? {
            0x00 => Ok(SessionType::Hmac),
            0x01 => Ok(SessionType::Policy),
            0x03 => Ok(SessionType::Trial),
            _ => Err(Fmt1::Value),
        }
    }
}

/// Starts a session (`SessionCreate`): its first nonce is as long as the caller's, and its
/// key is `KDFa(authHash, bindAuth || salt, "ATH", nonceTPM, nonceCaller, digest bits)` when it
/// is bound or salted, empty otherwise.
#[allow(clippy::too_many_arguments)]
pub fn start(
    platform: &mut impl Platform,
    kind: SessionType,
    auth_hash: Hash,
    nonce_caller: &[u8],
    symmetric: SymDef,
    bind: Option<(&[u8], &AuthValue, Da)>,
    salt: &[u8],
) -> Session {
    let mut nonce = vec![0u8; nonce_caller.len()];
    platform.fill_random(&mut nonce);
    let session_key = if bind.is_some() || !salt.is_empty() {
        let mut key = Zeroizing::new(Vec::new());
        if let Some((_, value, _)) = bind {
            key.extend_from_slice(value.key_material());
        }
        key.extend_from_slice(salt);
        let k = crypto::kdfa(
            auth_hash,
            &key,
            b"ATH",
            &nonce,
            nonce_caller,
            (auth_hash.size() * 8) as u32,
        );
        Secret::from_slice(&k).expect("a digest-sized key")
    } else {
        Secret::empty()
    };
    let da_bound = bind.is_some_and(|(_, _, da)| da != Da::Exempt);
    let core = Core {
        auth_hash,
        nonce_tpm: Buf::from_slice(&nonce).expect("nonce no longer than a digest"),
        symmetric,
        session_key,
        da_bound,
        lockout_bound: bind.is_some_and(|(_, _, da)| da == Da::Lockout),
    };
    match kind {
        SessionType::Hmac => Session::Hmac(HmacSession {
            core,
            bound: bind.map(|(name, value, _)| bind_id(name, value)),
        }),
        SessionType::Policy | SessionType::Trial => Session::Policy(PolicySession {
            core,
            trial: kind == SessionType::Trial,
            digest: [0; 32],
            auth_value_needed: false,
            password_needed: false,
            command_code: None,
            pcr_counter: None,
        }),
    }
}

// In the state file.

impl Marshal for AuthValue {
    fn write(&self, w: &mut Writer) {
        self.0.write(w);
    }
}

impl Unmarshal for AuthValue {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(AuthValue(Buf::read(r)?))
    }
}

/// The counter and the parameters, which the reference keeps in NV; the timers start again at
/// every Startup and are not saved.
impl Marshal for Lockout {
    fn write(&self, w: &mut Writer) {
        w.u32(self.failed_tries);
        w.u32(self.max_tries);
        w.u32(self.recovery_time);
        w.u32(self.lockout_recovery);
        self.lockout_auth_enabled.write(w);
    }
}

impl Lockout {
    /// In a snapshot: [`Marshal`]'s form, then the timers it leaves out, which a Startup
    /// restarts but a resumed TPM goes on with.
    pub fn write_live(&self, w: &mut Writer) {
        self.write(w);
        w.u64(self.now);
        w.u64(self.self_heal_timer);
        w.u64(self.lockout_timer);
    }

    pub fn read_live(r: &mut Reader<'_>) -> Result<Lockout, Fmt1> {
        let mut l = Lockout::read(r)?;
        l.now = r.u64()?;
        l.self_heal_timer = r.u64()?;
        l.lockout_timer = r.u64()?;
        Ok(l)
    }
}

impl Unmarshal for Lockout {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(Lockout {
            failed_tries: r.u32()?,
            max_tries: r.u32()?,
            recovery_time: r.u32()?,
            lockout_recovery: r.u32()?,
            lockout_auth_enabled: bool::read(r)?,
            now: 0,
            self_heal_timer: 0,
            lockout_timer: 0,
        })
    }
}

/// What a Restart or Resume needs of the table: the sequence the next saved session gets, and
/// which slots hold saved sessions. A loaded session does not survive `_TPM_Init`, so it is
/// written as a free slot.
impl Marshal for SessionTable {
    fn write(&self, w: &mut Writer) {
        w.u64(self.next_sequence);
        for slot in &self.slots {
            match slot {
                SessionSlot::Free | SessionSlot::Loaded(_) => w.u8(0),
                SessionSlot::Saved { sequence, kind } => {
                    w.u8(1);
                    w.u64(*sequence);
                    w.u8(*kind);
                }
            }
        }
    }
}

impl SessionTable {
    /// The whole table for a snapshot: [`Marshal`]'s form, but with each loaded session in
    /// full where that writes a free slot.
    pub fn write_live(&self, w: &mut Writer) {
        w.u64(self.next_sequence);
        for slot in &self.slots {
            match slot {
                SessionSlot::Free => w.u8(0),
                SessionSlot::Saved { sequence, kind } => {
                    w.u8(1);
                    w.u64(*sequence);
                    w.u8(*kind);
                }
                SessionSlot::Loaded(s) => {
                    w.u8(2);
                    s.write(w);
                }
            }
        }
    }

    /// What [`SessionTable::write_live`] wrote: no more loaded sessions than the TPM holds.
    pub fn read_live(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let next_sequence = r.u64()?;
        let mut slots = Vec::with_capacity(MAX_ACTIVE_SESSIONS);
        for _ in 0..MAX_ACTIVE_SESSIONS {
            slots.push(match r.u8()? {
                0 => SessionSlot::Free,
                1 => SessionTable::read_saved(r)?,
                2 => SessionSlot::Loaded(Box::new(Session::read(r)?)),
                _ => return Err(Fmt1::Value),
            });
        }
        let table = SessionTable { slots, next_sequence };
        if table.loaded() > MAX_LOADED_SESSIONS {
            return Err(Fmt1::Size);
        }
        Ok(table)
    }

    /// Whether any session is loaded: none is in a table a Restart or Resume carries.
    pub fn has_loaded(&self) -> bool {
        self.loaded() > 0
    }

    fn read_saved(r: &mut Reader<'_>) -> Result<SessionSlot, Fmt1> {
        let sequence = r.u64()?;
        let kind = r.u8()?;
        if kind != ht::HMAC_SESSION && kind != ht::POLICY_SESSION {
            return Err(Fmt1::Value);
        }
        Ok(SessionSlot::Saved { sequence, kind })
    }
}

impl Unmarshal for SessionTable {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let next_sequence = r.u64()?;
        let slots = (0..MAX_ACTIVE_SESSIONS)
            .map(|_| match r.u8()? {
                0 => Ok(SessionSlot::Free),
                1 => SessionTable::read_saved(r),
                _ => Err(Fmt1::Value),
            })
            .collect::<Result<_, _>>()?;
        Ok(SessionTable { slots, next_sequence })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(bytes: &[u8]) -> AuthValue {
        AuthValue::from_slice(bytes)
    }

    #[test]
    fn trailing_zeros_do_not_change_a_password() {
        assert!(auth(b"pw").matches(b"pw\0\0"));
        assert!(auth(b"pw\0").matches(b"pw"));
        assert!(!auth(b"pw").matches(b"p"));
        assert!(auth(b"").matches(b""));
        assert!(auth(b"").matches(b"\0"));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn trimmed(b: &[u8]) -> &[u8] {
        let mut end = b.len();
        while end > 0 && b[end - 1] == 0 {
            end -= 1;
        }
        &b[..end]
    }

    /// A presented password matches an authValue exactly when the two are equal with their
    /// trailing zeros removed, for every pair up to four bytes. The bound covers the 32-byte
    /// buffer an `AuthValue` zeroizes when dropped.
    #[kani::proof]
    #[kani::unwind(34)]
    fn a_password_matches_its_value_up_to_trailing_zeros() {
        let value: [u8; 4] = kani::any();
        let presented: [u8; 4] = kani::any();
        let vl: usize = kani::any_where(|l| *l <= 4);
        let pl: usize = kani::any_where(|l| *l <= 4);
        let v = AuthValue::from_slice(&value[..vl]);
        assert!(
            v.matches(&presented[..pl]) == (trimmed(&value[..vl]) == trimmed(&presented[..pl]))
        );
    }
}
