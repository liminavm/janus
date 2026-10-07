// SPDX-License-Identifier: MIT OR Apache-2.0

//! janus: a TPM 2.0 engine for virtual machines.
//!
//! The engine takes command bytes and returns response bytes. It knows nothing about the
//! interface a guest reaches it through (a TIS register file, a CRB, a socket), nor about where
//! its state is kept: the device that owns a [`Janus`] delivers commands with their locality,
//! signals a platform reset with [`Janus::init`], and supplies randomness through [`Platform`].
//!
//! It implements the commands its consumers send, measured from real guests, not the whole
//! TPM 2.0 Library specification. An unimplemented command answers `TPM_RC_COMMAND_CODE`.

#![forbid(unsafe_code)]

#[macro_use]
mod marshal;
mod alg;
mod capability;
mod cc;
mod command;
mod context;
mod crypto;
mod handle;
mod hierarchy;
mod object;
mod pcr;
pub mod rc;
mod sequence;
mod session;
mod tpm;
mod types;
mod wire;

pub use tpm::Janus;

/// The locality a command arrived at, 0 to 4. Extended localities are not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locality(u8);

impl Locality {
    pub const ZERO: Locality = Locality(0);

    pub const fn new(n: u8) -> Option<Locality> {
        if n <= 4 { Some(Locality(n)) } else { None }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    /// The locality's bit in a PCR's locality mask, and as `TPMA_LOCALITY` reports it.
    const fn bit(self) -> u8 {
        1 << self.0
    }
}

/// What the engine needs from the host it runs on.
pub trait Platform {
    /// Fills `buf` from a cryptographically secure source.
    fn fill_random(&mut self, buf: &mut [u8]);

    /// Milliseconds on a monotonic clock. Only differences between readings are used: the
    /// TPM's `Clock` advances by them while the TPM runs, and its `Time` counts them since
    /// `_TPM_Init`. A reading lower than the one before counts as no time.
    fn now_ms(&mut self) -> u64;
}
