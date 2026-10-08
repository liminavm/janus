# janus

A TPM 2.0 engine for virtual machines, in safe Rust. It takes command bytes and returns response
bytes; the device that owns it supplies the locality, platform resets and randomness. Written for
limina's virtual TPM.

## Status

The 42 commands its consumers use: lifecycle (`Startup`, `Shutdown`, `SelfTest`,
`GetTestResult`), capabilities, randomness and the clock; PCRs (`PCR_Read`, `PCR_Extend`);
primary, ordinary and sealed objects (`CreatePrimary`, `Create`, `Load`, `ReadPublic`, `Unseal`,
`EvictControl`); signing and decryption (`Sign`, `RSA_Decrypt`, `ECC_Parameters`, `TestParms`);
hashing and hash sequences; HMAC and policy sessions (`StartAuthSession` with salting, binding and
AES-128-CFB parameter encryption; `PolicyPCR`, `PolicyAuthValue`, `PolicyPassword`,
`PolicyCommandCode`, `PolicyGetDigest`, `PolicyRestart`); context save, load and flush; NV indexes
(define, undefine, read, write, extend, read public); dictionary-attack protection. That is every
command a stock Fedora guest's systemd (credentials, cryptenroll, PCR policies), clevis,
ssh-tpm-agent, tpm2-pkcs11, the tpm2 OpenSSL provider, the kernel and edk2's measured boot send.

The device that owns a TPM keeps it with [`Janus::state`] (what NV holds, for a file across power
cycles) or [`Janus::snapshot`] (everything, volatile state included, for a suspended machine).

## Known gaps

- **Algorithms.** SHA-256, HMAC, AES-128-CFB, RSA-2048 and ECC P-256, one SHA-256 PCR bank.
  `TestParms` refuses the rest, so a client asking explicitly for a larger key fails.
- **Commands.** No `Import`, `PolicyAuthorize`, `PolicySigned` or `PolicySecret`; an
  unimplemented command answers `TPM_RC_COMMAND_CODE`.
- **Identity.** No endorsement-key certificate: nothing vouches that this TPM is a TPM.
- **Capacity.** Three loaded objects, three loaded sessions, seven persistent objects.

## Licence

MIT OR Apache-2.0, at your option (`LICENSES/`).
