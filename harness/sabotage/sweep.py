#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Break the engine on purpose, and report which breakages the checkers notice.

A passing test or proof says nothing about what it would catch. Each entry below is a small edit
that makes janus wrong in a way a guest could exploit or observe, applied alone to a clean file,
checked by its witness, and reverted. `RED` is the witness catching it; `SURVIVED` is a hole.

    harness/sabotage/sweep.py [pattern ...]

Entries match by substring of their name; with none, every entry runs. Every edit is an exact
string replacement that must match once, and all targets are checked before anything builds, so
a refactor that moves a target fails loudly instead of quietly testing nothing.

A witness is a `cargo test` filter, or `kani:<harness>` for one Kani proof.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# (name, file, what to replace, what with, witness)
SABOTAGES = [
    (
        'a command whose header size disagrees with its length is framed',
        'src/command.rs',
        'if size as usize != bytes.len() || size > MAX_COMMAND_SIZE {',
        'if size as usize > bytes.len() || size > MAX_COMMAND_SIZE {',
        'kani:a_frame_has_exactly_the_size_its_header_claims',
    ),
    (
        'a TPM2B may be one byte longer than its bound',
        'src/wire.rs',
        '        if n > MAX {',
        '        if n > MAX + 1 {',
        'kani:tpm2b_reads_exactly_what_it_claims',
    ),
    (
        'a second Startup is dispatched to the running TPM',
        'src/tpm.rs',
        'Lifecycle::Running(tpm) if cmd.cc == Cc::Startup =>',
        'Lifecycle::Running(tpm) if false && cmd.cc == Cc::Startup =>',
        'lifecycle',
    ),
    (
        'a PCR that is not state-saved survives Startup(STATE)',
        'src/pcr.rs',
        '            if p.attributes().state_saved {',
        '            if true {',
        'lifecycle',
    ),
    (
        'the lockout hierarchy is exempt from dictionary-attack protection',
        'src/tpm.rs',
        '        *self != HierarchyAuth::Lockout',
        '        true',
        'a_wrong_lockout_password_locks_lockout_authorization',
    ),
    (
        'any locality may extend any PCR',
        'src/pcr.rs',
        'p.attributes().extend & locality.bit() != 0',
        'p.attributes().extend | locality.bit() != 0',
        'a_pcr_extends_only_from_its_localities',
    ),
    (
        'TPM_RH_NULL is refused as a PCR_Extend target',
        'src/handle.rs',
        '        if h == rh::NULL {\n            return Some(PcrOrNull::Null);',
        '        if h == rh::NULL + 1 {\n            return Some(PcrOrNull::Null);',
        'kani:pcr_or_null_accepts_exactly_the_pcrs_and_null',
    ),
    (
        'a leftover password session is accepted',
        'src/session.rs',
        '        if handles < self.sessions.len() {',
        '        if false && handles < self.sessions.len() {',
        'malformed_session_areas_are_refused_with_the_reference_codes',
    ),
    (
        'a password with trailing zeros is compared as sent',
        'src/session.rs',
        '        while end > 0 && presented[end - 1] == 0 {',
        '        while false && end > 0 && presented[end - 1] == 0 {',
        'a_wrong_hierarchy_password_is_bad_auth_on_the_session',
    ),
]


def witness(w):
    if w.startswith('kani:'):
        return ['cargo', 'kani', '--harness', w[5:], '--exact']
    return ['cargo', 'test', '--quiet', w]


def main(patterns):
    chosen = [s for s in SABOTAGES if not patterns or any(p in s[0] for p in patterns)]
    bad = []
    for name, path, old, _, _ in chosen:
        n = (ROOT / path).read_text().count(old)
        if n != 1:
            bad.append(f'{name}: {path} has {n} matches for its target')
    if bad:
        sys.exit('\n'.join(bad))
    survived = []
    for name, path, old, new, w in chosen:
        f = ROOT / path
        clean = f.read_text()
        f.write_text(clean.replace(old, new))
        try:
            r = subprocess.run(witness(w), cwd=ROOT, capture_output=True)
        finally:
            f.write_text(clean)
        verdict = 'RED' if r.returncode != 0 else 'SURVIVED'
        print(f'{verdict:9} {name}  [{w}]', flush=True)
        if verdict == 'SURVIVED':
            survived.append(name)
    if survived:
        sys.exit(f'{len(survived)} sabotage(s) survived')


if __name__ == '__main__':
    main(sys.argv[1:])
