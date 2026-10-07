# janus

A TPM 2.0 engine for virtual machines, in safe Rust. It takes command bytes and returns response
bytes; the device that owns it supplies the locality, platform resets and randomness. Written for
limina's virtual TPM.

## Status

Implemented: `TPM2_Startup`, `TPM2_Shutdown`, `TPM2_SelfTest`, `TPM2_GetCapability`,
`TPM2_GetRandom`, `TPM2_PCR_Read`, `TPM2_PCR_Extend` and `TPM2_HierarchyChangeAuth`, with
password sessions and one SHA-256 PCR bank. That covers an edk2 measured boot: the firmware part of
a captured Fedora boot replays byte for byte against swtpm's answers, up to the kernel's first
`TPM2_CreatePrimary`.

Next: HMAC and policy sessions (`TPM2_StartAuthSession` with an ECC salt and AES-128-CFB
parameter encryption), `TPM2_CreatePrimary` for P-256, and context save, load and flush, which
the kernel's resource manager needs before anything else.

## Known gaps

- **Lockout recovery.** A failed lockout authorization locks lockout authorization until the TPM
  is manufactured again; `lockoutRecovery` needs a clock, which janus does not have yet.
- **Context sizes.** `TPM_PT_MAX_OBJECT_CONTEXT` and `TPM_PT_MAX_SESSION_CONTEXT` report the bounds
  the context format is planned to fit; they must be recomputed when that format exists.
- **Orderly shutdown.** `TPM2_Shutdown(STATE)` saves the PCRs a resume restores. Clock, the reset
  and restart counts, and the other state an orderly shutdown governs arrive with the features
  that own them.

## Licence

MIT OR Apache-2.0, at your option (`LICENSES/`).
