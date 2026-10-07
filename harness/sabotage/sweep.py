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
        'if h == HierarchyAuth::Lockout { Da::Lockout } else { Da::Exempt }',
        'if h == HierarchyAuth::Lockout { Da::Exempt } else { Da::Exempt }',
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
        'SessionRef::Password if i >= auth_handles => {',
        'SessionRef::Password if false && i >= auth_handles => {',
        'malformed_session_areas_are_refused_with_the_reference_codes',
    ),
    (
        'a password with trailing zeros is compared as sent',
        'src/session.rs',
        '        while end > 0 && presented[end - 1] == 0 {',
        '        while false && end > 0 && presented[end - 1] == 0 {',
        'a_wrong_hierarchy_password_is_bad_auth_on_the_session',
    ),
    (
        "a saved context's integrity leaves out its sequence",
        'src/context.rs',
        'parts.extend([&seq[..], &h[..], encrypted]);',
        'parts.extend([&h[..], encrypted]);',
        'the_context_format_is_pinned',
    ),
    (
        "an stClear object's context survives a Restart",
        'src/context.rs',
        '    if handle == SavedHandle::StClear {',
        '    if false {',
        'an_st_clear_objects_context_dies_at_a_restart',
    ),
    (
        "a saved context's integrity is not checked",
        'src/context.rs',
        'if !crypto::constant_time_eq(&expected, tag.get()) {',
        'if false {',
        'a_context_that_was_tampered_with_or_names_no_context_is_refused',
    ),
    (
        'TPMI_DH_SAVED accepts a session handle past the session table',
        'src/context.rs',
        'let in_range = (h & 0x00FF_FFFF) < MAX_ACTIVE_SESSIONS as u32;',
        'let in_range = true;',
        'kani:saved_handles_are_exactly_tpmi_dh_saved',
    ),
    (
        'a session context loads over a loaded session',
        'src/session.rs',
        '            _ => return Err(Rc::Fmt1(Fmt1::Handle, Some(At::param(1)))),',
        '            _ => {}',
        'a_saved_session_loads_back_once_and_keeps_working',
    ),
    (
        "a session's HMAC is not compared",
        'src/session.rs',
        '&& bool::from(expected.ct_eq(e.hmac.as_slice()))',
        '&& true',
        'a_wrong_hmac_is_bad_auth_and_leaves_the_session_usable',
    ),
    (
        "a response leaves the TPM's nonce as it was",
        'src/session.rs',
        'core.nonce_tpm = Buf::from_slice(&nonce).expect("same size as before");',
        'let _ = &nonce;',
        'the_kernels_boot_sequence_works_against_its_own_key',
    ),
    (
        "a bound session's HMAC key includes the bound entity's authValue",
        'src/session.rs',
        'self.entries[i].include_auth = !bound;',
        'self.entries[i].include_auth = true;',
        'a_bound_session_changes_an_authorization_it_sends_encrypted',
    ),
    (
        'a session that authorizes nothing need not encrypt or audit',
        'src/session.rs',
        'if !e.attributes.encrypt() && !e.attributes.decrypt() && !e.attributes.audit() {',
        'if false {',
        'a_session_that_authorizes_nothing_must_encrypt_or_decrypt',
    ),
    (
        "an object whose private part is another type than its public part reads",
        'src/object.rs',
        'if sensitive.kind.selector() != public.kind.selector() {',
        'if false {',
        'an_object_whose_parts_disagree_does_not_read',
    ),
    (
        'a ContextSave after Shutdown(STATE) leaves the save to resume',
        'src/tpm.rs',
        '        if clear_orderly {',
        '        if false {',
        'saving_a_context_after_shutdown_state_makes_the_resume_a_reset',
    ),
    (
        'a Restart regenerates the null hierarchy like a Reset',
        'src/tpm.rs',
        '(StartupType::Clear, Some(Orderly::State(saved)), Some(c)) =>',
        '(StartupType::Clear, Some(Orderly::State(saved)), Some(c)) if false =>',
        'saved_contexts_outlive_a_resume_and_a_restart_but_not_a_reset',
    ),
    (
        "CreatePrimary skips the template's attribute checks",
        'src/tpm.rs',
        'object::validate_template(&template, sensitive.data.as_slice().len(), None)',
        'Ok::<(), Fmt1>(())',
        'create_primary_refuses_templates_in_the_reference_order',
    ),
    (
        'creation data reports no locality',
        'src/tpm.rs',
        '            locality: locality.bit(),',
        '            locality: 0,',
        'a_boot_replays_up_to_the_kernels_first_session',
    ),
    (
        'a private area whose integrity does not verify is decrypted and loaded',
        'src/object.rs',
        'if !crypto::constant_time_eq(&expected, tag.get()) {',
        'if false && !crypto::constant_time_eq(&expected, tag.get()) {',
        'load_refuses_private_areas_in_the_reference_order',
    ),
    (
        'a policy satisfied before a PCR changed still authorizes',
        'src/session.rs',
        'if p.pcr_counter.is_some_and(|c| c != pcr_counter) {',
        'if false && p.pcr_counter.is_some_and(|c| c != pcr_counter) {',
        'a_secret_sealed_to_pcr7_and_a_password_unseals_until_pcr7_moves',
    ),
    (
        'a policy session authorizes whatever policy it holds',
        'src/session.rs',
        'if !bool::from(p.digest[..].ct_eq(auth.policy)) {',
        'if false && !bool::from(p.digest[..].ct_eq(auth.policy)) {',
        'a_secret_sealed_to_pcr7_and_a_password_unseals_until_pcr7_moves',
    ),
    (
        'a policy session keeps its policy after authorizing a command',
        'src/session.rs',
        'p.restart();',
        'let _ = p;',
        'a_secret_sealed_to_pcr7_and_a_password_unseals_until_pcr7_moves',
    ),
    (
        'PolicyAuthValue leaves the authValue out of the session HMAC',
        'src/tpm.rs',
        'p.auth_value_needed = cc == Cc::PolicyAuthValue;',
        'p.auth_value_needed = false;',
        'a_secret_sealed_to_pcr7_and_a_password_unseals_until_pcr7_moves',
    ),
    (
        'data that starts like an attestation gets a hash ticket',
        'src/tpm.rs',
        'data.starts_with(&TPM_GENERATED_VALUE.to_be_bytes())',
        'data.starts_with(&[0xA5u8; 4])',
        'hash_tickets_only_what_the_tpm_could_not_have_produced',
    ),
    (
        'any object is a parent',
        'src/object.rs',
        'a.restricted() && a.decrypt() && !a.sign_encrypt()',
        'true',
        'load_refuses_private_areas_in_the_reference_order',
    ),
    (
        'Unseal hands out an HMAC key',
        'src/tpm.rs',
        'if a.decrypt() || a.sign_encrypt() || a.restricted() {',
        'if a.decrypt() || a.restricted() {',
        'load_refuses_private_areas_in_the_reference_order',
    ),
    (
        'PolicyCommandCode accepts a command janus does not implement',
        'src/tpm.rs',
        'if Cc::from_code(target).is_none() {',
        'if false && Cc::from_code(target).is_none() {',
        'policy_commands_refuse_what_is_not_a_loaded_policy_session',
    ),
    (
        "a restricted key signs a digest with no ticket",
        "src/tpm.rs",
        "if !ticket.digest.as_slice().is_empty() || a.restricted() {",
        "if !ticket.digest.as_slice().is_empty() {",
        "ecc_keys_sign_and_restricted_ones_only_what_the_tpm_hashed",
    ),
    (
        "Sign accepts any hash-check ticket",
        "src/tpm.rs",
        "if !crypto::constant_time_eq(&expected, ticket.digest.as_slice()) {",
        "if false && !crypto::constant_time_eq(&expected, ticket.digest.as_slice()) {",
        "ecc_keys_sign_and_restricted_ones_only_what_the_tpm_hashed",
    ),
    (
        "a key that cannot sign signs",
        "src/tpm.rs",
        "if !a.sign_encrypt() || matches!(o.public.kind, PublicKind::SymCipher(_)) {",
        "if matches!(o.public.kind, PublicKind::SymCipher(_)) {",
        "an_rsa_storage_key_is_the_same_key_every_time_and_parents_keys",
    ),
    (
        "RSA_Decrypt takes a label without its NUL",
        "src/tpm.rs",
        "if label.last().is_some_and(|b| *b != 0) {",
        "if false && label.last().is_some_and(|b| *b != 0) {",
        "an_rsa_storage_key_is_the_same_key_every_time_and_parents_keys",
    ),
    (
        "a restricted key decrypts for RSA_Decrypt",
        "src/tpm.rs",
        "if a.restricted() || !a.decrypt() {",
        "if !a.decrypt() {",
        "an_rsa_storage_key_is_the_same_key_every_time_and_parents_keys",
    ),
    (
        "an RSA exponent below 65537 is generated",
        "src/crypto.rs",
        "(e >= RSA_DEFAULT_EXPONENT && prime).then_some(e)",
        "prime.then_some(e)",
        "rsa_exponents_are_zero_or_primes_from_65537",
    ),
    (
        "RSA derivation moves",
        "src/crypto.rs",
        "b[0] |= 0xC0;",
        "b[0] |= 0x80;",
        "rsa_derivation_is_pinned",
    ),
    (
        "an RSA salt decrypts under another label",
        "src/tpm.rs",
        "const SECRET_LABEL: &[u8] = b\"SECRET\\0\";",
        "const SECRET_LABEL: &[u8] = b\"SECRET\";",
        "a_session_salted_to_an_rsa_key_derives_the_key_the_client_does",
    ),
    (
        "a hash-check ticket reads with any tag",
        "src/types.rs",
        "if r.u16()? != ST_HASHCHECK {",
        "if r.u16()? == 0 {",
        "kani:a_hash_check_ticket_reads_only_its_tag_and_a_hierarchy",
    ),
    (
        "a sequence tickets data whose first block starts like an attestation",
        "src/sequence.rs",
        "*ticket_safe = ticket_safe_data(data);",
        "*ticket_safe = true;",
        "a_hash_sequence_survives_its_context_and_tickets_what_a_restricted_key_signs",
    ),
    (
        "a saved hash state may claim any pending length",
        "src/sequence.rs",
        "if pending.get().len() as u64 != len % 64 {",
        "if false && pending.get().len() as u64 != len % 64 {",
        "kani:a_hash_state_reads_only_a_state_a_hash_could_reach",
    ),
    (
        "a sequence's wrong password counts toward lockout",
        "src/tpm.rs",
        "            da: Da::Exempt,\n            value_available: true,\n        };\n        auth.authorize(\n            &self.stage.reset.sessions,\n            params,\n            q,",
        "            da: Da::Protected,\n            value_available: true,\n        };\n        auth.authorize(\n            &self.stage.reset.sessions,\n            params,\n            q,",
        "a_hash_sequence_survives_its_context_and_tickets_what_a_restricted_key_signs",
    ),
    (
        "a Startup after no orderly shutdown leaves the clock safe",
        "src/tpm.rs",
        "        if !was_orderly {",
        "        if false && !was_orderly {",
        "the_clock_runs_while_the_tpm_does_and_time_since_init",
    ),
    (
        "a platform clock that steps back makes the TPM clock run twice",
        "src/tpm.rs",
        "        self.clocks.last = self.clocks.last.max(now);",
        "        self.clocks.last = now;",
        "the_clock_runs_while_the_tpm_does_and_time_since_init",
    ),
    (
        "a Resume does not count as a restart",
        "src/tpm.rs",
        "                let mut reset = c.reset;\n                reset.restart_count = reset.restart_count.wrapping_add(1);\n                (Pcrs::resume(",
        "                let reset = c.reset;\n                (Pcrs::resume(",
        "the_clock_runs_while_the_tpm_does_and_time_since_init",
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
