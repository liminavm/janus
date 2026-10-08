# janus

A TPM 2.0 engine in Rust, for limina's virtual TPM. The device design, the decisions behind it
and the phase plan are in limina's `docs/design/vtpm.md`; this file is how to work on the engine.

janus implements the commands its consumers send, measured from real guests (limina's
`spikes/vtpm-p0`, whose captures are `tests/corpus/`), not the whole TPM 2.0 Library
specification. The TCG reference implementation and swtpm/libtpms are **oracles**: we read the
reference to learn what a command must answer and replay swtpm's answers to check we give the
same. No code is taken from either.

## Why Rust, and what follows from it

A TPM holds secrets a guest trusts it with, and every byte it parses comes from that guest. The
language is meant to remove whole classes of bugs from that combination. Every rule below is that
reason, applied.

**No `unsafe`.** `unsafe_code = "forbid"`. A TPM is parsing and arithmetic; nothing in it needs a
raw pointer. A change that wants one has the wrong types.

**Make bad state unrepresentable.** The TPM wire is bare `u32` handles, `u16` algorithm ids and
`u32` response codes, all interchangeable and none checked. Each gets its own type, built only by
the parser that validated it: a `PcrIndex` is a PCR that exists, an `Authorized<E>` is an entity
whose authorization was checked (its only constructor is the session check), an `Rc` cannot be
a format-1 code with session index 9. Where something is valid in one state only, that state is
a type: a TPM before `TPM2_Startup` is `Tpm<Initialized>` and has no PCRs to extend.

**A guest never panics us.** Malformed, hostile or nonsensical commands are response codes, never
panics: `Janus::execute` returns bytes for every input, and the fuzzers hold it to that. An
`assert!`/`.expect()` is for a violated *engine* invariant — something we got wrong — and says
which.

**Answer the way the reference answers.** Clients branch on response codes, including their
position fields. When we reject something, the code, its position, and which check fires first
follow the reference's order (`ExecCommand.c`, `SessionProcess.c`); a test names the code it
expects and cites where the reference returns it.

**Two values that must agree are one value.** The header's `commandSize` and the buffer's length
are reconciled once, in `command::frame`, and a `TPM2B`'s size and its bytes become one
`Bytes<MAX>`. Nothing past the boundary sees the pair.

**No global state.** Everything hangs off a `Janus`, and its owner (the device) decides where the
state lives and when it is saved.

**Secrets are zeroized and compared in constant time.** `AuthValue` and every type holding key
material zeroizes on drop, has no `Debug` and no `Clone`, and compares with `subtle`.

**The crate does not choose a panic strategy.** It is a library; the binary that links it does.

## Checkers

Each property is held by the cheapest checker that can hold it, and every checker is armed:

- `cargo test` — unit tests beside the code; `tests/commands.rs` (behaviour guests never
  exercise: wrong passwords, lockout, locality, malformed session areas, refused contexts);
  `tests/replay.rs` (the guest corpus against swtpm's answers, up to the first command an HMAC
  or policy session protects); `tests/sessions.rs` (a client written from the specification
  that takes over from there: salted, bound and encrypting sessions, every response HMAC
  checked); `tests/every_sequence.rs` (exhaustive walks of the lifecycle against a model, which
  also assert they reached every case they exist for).
- `cargo kani` — proofs in `#[cfg(kani)] mod proofs` beside the code they prove, for properties
  over every input of a bounded size: the wire reader, framing, handle classification, response
  code assembly.
- `cargo +nightly fuzz run <target>` in `fuzz/` (its own workspace) — `execute` (one command into
  a started TPM), `sequence` (commands, resets and locality changes), `prepared` (the same,
  into a TPM already holding a key, a session and saved contexts), `state` (a state file's
  body, which must be refused or restore to a TPM that saves it back byte for byte) and
  `snapshot` (the same for a snapshot, which must also answer commands as it resumes). Every
  response must be a well-formed frame. Seed the corpora from the guest captures first:
  `cargo run --manifest-path fuzz/Cargo.toml --bin seed-corpora`.
- Miri — `RUSTFLAGS='--cfg sha2_backend="soft"' cargo +nightly miri test --lib` and
  `--test commands` (about 1.5 h together; cap them). The unsafe code is all in dependencies,
  and these are the suites that reach it without generating RSA keys, which Miri cannot finish;
  `sessions`, `replay` and the walks stay out. The flag picks sha2's portable backend: sha2
  0.11.0's aarch64 one reads 16 bytes through a reference to one `u32`, which Stacked Borrows
  rejects (fixed upstream, unreleased); drop it once a release carries the fix.
- `harness/sabotage/sweep.py` — breaks each guarded property on purpose and checks its witness
  goes red. A new guard gets an entry; an entry that survives is a hole.

A new command lands with: its reference-ordered checks as unit or `commands.rs` tests, the corpus
replay advanced past it, a proof for any new parser, and a sabotage entry for any new guard.

## Working here

- `cargo fmt` follows `rustfmt.toml` (style edition 2024); keep `cargo clippy -- -D warnings`
  clean.
- The crates.io name `janus` is taken; this crate is not published and limina consumes it by path.
- Commit as work finishes. Never `git add -A`. Never push without asking.

## Commit messages

`area: <imperative verb> <concrete object>`, at most 72 characters. The body, wrapped at 72: the
problem as observable behaviour, what the commit changes, how it was verified. Code identifiers
in backticks; no first person.

## Licensing

MIT OR Apache-2.0 (`LICENSES/`), so it links into Apache-2.0 libkrun and anything else. New files
take the SPDX header `MIT OR Apache-2.0`.
