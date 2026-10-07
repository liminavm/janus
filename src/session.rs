// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authorization area and the proof that an entity was authorized.
//!
//! A command handler that acts on an entity needing authorization takes an [`Authorized`] for
//! it, and only [`AuthArea::authorize`] makes one, after the session for that handle has been
//! checked. A handler cannot forget the check because it cannot get the entity without it.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::alg::MAX_DIGEST;
use crate::handle::AuthSessionHandle;
use crate::rc::{At, Fmt0, Fmt1, Index, Rc, Slot, Warn};
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
        let mut buf = Buf::from_wire(b);
        buf.trim_trailing_zeros();
        AuthValue(buf)
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_slice().is_empty()
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

/// `TPMA_SESSION` bits.
mod attr {
    pub const CONTINUE_SESSION: u8 = 0x01;
    pub const AUDIT_EXCLUSIVE: u8 = 0x02;
    pub const AUDIT_RESET: u8 = 0x04;
    pub const RESERVED: u8 = 0x18;
    pub const DECRYPT: u8 = 0x20;
    pub const ENCRYPT: u8 = 0x40;
    pub const AUDIT: u8 = 0x80;
}

/// One session from the authorization area, as the wire carries it.
struct Session<'a> {
    handle: AuthSessionHandle,
    /// The HMAC field, which for a password session is the password.
    hmac: Bytes<'a, MAX_DIGEST>,
}

/// An entity a session can authorize. Whether a failed authorization counts towards dictionary
/// attack lockout depends on what the entity is.
pub trait Entity: Copy {
    /// Exempt from dictionary-attack protection: every permanent handle except lockout, and
    /// every PCR (Part 1 §19.8.4).
    fn da_exempt(&self) -> bool;
}

/// Proof that the session for `entity` was checked. Only [`AuthArea::authorize`] makes one.
pub struct Authorized<E> {
    entity: E,
}

impl<E: Copy> Authorized<E> {
    pub fn entity(&self) -> E {
        self.entity
    }
}

/// The dictionary-attack state the authorization check reads and updates.
pub struct Lockout {
    /// The lockout hierarchy's own authorization failed, which disables it until recovery.
    pub lockout_auth_failed: bool,
}

/// What the dispatcher knows about the command's sessions before its handles are authorized.
pub struct AuthArea<'a> {
    sessions: Vec<Session<'a>>,
    /// How many sessions [`AuthArea::bind`] tied to handles.
    bound: usize,
    /// How many of those [`AuthArea::authorize`] has checked.
    next: usize,
}

impl<'a> AuthArea<'a> {
    /// A command without an authorization area (`TPM_ST_NO_SESSIONS`).
    pub fn none() -> AuthArea<'a> {
        AuthArea { sessions: Vec::new(), bound: 0, next: 0 }
    }

    /// Reads the authorization area of a `TPM_ST_SESSIONS` command. `sessions_allowed` is false
    /// for a command that takes none (`TPM2_Startup`).
    pub fn read(r: &mut Reader<'a>, sessions_allowed: bool) -> Result<AuthArea<'a>, Rc> {
        let size = r.u32().map_err(Rc::bare)?;
        if size < MIN_SESSION_SIZE || size as usize > r.remaining() {
            return Err(Rc::bare(Fmt1::Size));
        }
        if !sessions_allowed {
            return Err(Fmt0::AuthContext.into());
        }
        let mut area = r.split(size as usize).map_err(Rc::bare)?;
        let mut sessions = Vec::new();
        while !area.is_empty() {
            let n = sessions.len();
            let Some(i) = Index::<7>::new(n as u8 + 1) else {
                unreachable!("the loop stops at four sessions")
            };
            let at = At::Session(i);
            if n == MAX_SESSIONS {
                return Err(Rc::Fmt1(Fmt1::Size, Some(at)));
            }
            let handle = area.u32().at(at)?;
            let handle = AuthSessionHandle::from_handle(handle).ok_or(Fmt1::Value).at(at)?;
            let nonce = area.tpm2b::<MAX_DIGEST>().at(at)?;
            let attributes = area.u8().at(at)?;
            if attributes & attr::RESERVED != 0 {
                return Err(Rc::Fmt1(Fmt1::ReservedBits, Some(at)));
            }
            let hmac = area.tpm2b::<MAX_DIGEST>().at(at)?;
            match handle {
                AuthSessionHandle::Password => {
                    let not_auth_only = attr::ENCRYPT
                        | attr::DECRYPT
                        | attr::AUDIT
                        | attr::AUDIT_EXCLUSIVE
                        | attr::AUDIT_RESET;
                    if attributes & not_auth_only != 0 {
                        return Err(Rc::Fmt1(Fmt1::Attributes, Some(at)));
                    }
                    if !nonce.get().is_empty() {
                        return Err(Rc::Fmt1(Fmt1::Nonce, Some(at)));
                    }
                }
                // No HMAC or policy session can be loaded yet, so any such handle names a
                // session that is not there.
                AuthSessionHandle::Hmac(_) | AuthSessionHandle::Policy(_) => {
                    let slot = Slot::new(n as u8).expect("at most three sessions");
                    return Err(Warn::ReferenceS(slot).into());
                }
            }
            sessions.push(Session { handle, hmac });
        }
        Ok(AuthArea { sessions, bound: 0, next: 0 })
    }

    /// Binds sessions to the command's `handles` handles that need authorization, in order,
    /// before any is checked, as the reference does: a handle with no session is
    /// `TPM_RC_AUTH_MISSING`, and a session left over must be for audit or parameter encryption,
    /// which a password session cannot be (`TPM_RC_HANDLE` on that session).
    pub fn bind(&mut self, handles: usize) -> Result<(), Rc> {
        if handles > self.sessions.len() {
            return Err(Fmt0::AuthMissing.into());
        }
        // Every session read() accepts is a password session, so the first one left over is the
        // fault.
        if handles < self.sessions.len() {
            let at = At::Session(Index::new(handles as u8 + 1).expect("at most three sessions"));
            return Err(Rc::Fmt1(Fmt1::Handle, Some(at)));
        }
        self.bound = handles;
        self.next = 0;
        Ok(())
    }

    /// Checks the next bound session against `entity`, whose authorization value is `auth`.
    pub fn authorize<E: Entity>(
        &mut self,
        entity: E,
        auth: &AuthValue,
        lockout: &mut Lockout,
        is_lockout: bool,
    ) -> Result<Authorized<E>, Rc> {
        let n = self.next;
        assert!(n < self.bound, "authorize() called for more handles than bind() was given");
        self.next += 1;
        let session = &self.sessions[n];
        let at = At::Session(Index::new(n as u8 + 1).expect("at most three sessions"));
        match session.handle {
            AuthSessionHandle::Password => {
                if is_lockout && lockout.lockout_auth_failed {
                    return Err(Warn::Lockout.into());
                }
                if auth.matches(session.hmac.get()) {
                    return Ok(Authorized { entity });
                }
                if entity.da_exempt() {
                    return Err(Rc::Fmt1(Fmt1::BadAuth, Some(at)));
                }
                if is_lockout {
                    lockout.lockout_auth_failed = true;
                }
                Err(Rc::Fmt1(Fmt1::AuthFail, Some(at)))
            }
            AuthSessionHandle::Hmac(_) | AuthSessionHandle::Policy(_) => {
                unreachable!("read() refuses sessions that are not loaded")
            }
        }
    }

    /// Every bound session was checked. A dispatcher that binds more handles than it authorizes
    /// is an engine bug.
    pub fn finish(&self) {
        assert_eq!(self.next, self.bound, "a bound session was never checked");
    }

    /// The response's authorization area: one entry per command session, in order. A password
    /// session answers an empty nonce, `continueSession` set, and an empty HMAC.
    pub fn write_response(&self, w: &mut Writer) {
        for s in &self.sessions {
            match s.handle {
                AuthSessionHandle::Password => {
                    w.tpm2b(&[]);
                    w.u8(attr::CONTINUE_SESSION);
                    w.tpm2b(&[]);
                }
                AuthSessionHandle::Hmac(_) | AuthSessionHandle::Policy(_) => {
                    unreachable!("read() refuses sessions that are not loaded")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(bytes: &[u8]) -> AuthValue {
        let mut v = vec![0, bytes.len() as u8];
        v.extend_from_slice(bytes);
        AuthValue::from_wire(Reader::new(&v).tpm2b::<MAX_DIGEST>().unwrap())
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
