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

A witness is a `cargo test` filter, or `kani:<harness>` for one Kani proof. A witness that runs
past `WITNESS_TIMEOUT` is killed with everything it started and reported as `TIMEOUT`: a
sabotage that makes something loop forever must not take the sweep, or the host, with it.
"""

import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Seconds; the slowest witness (a Kani proof) takes a few minutes.
WITNESS_TIMEOUT = 1800

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
        '            locality: c.locality.bit(),',
        '            locality: 0,',
        'a_boot_replays_in_full',
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
    (
        "a persistent object borrows no transient slot",
        "src/tpm.rs",
        "                self.stage.borrowed.set(self.stage.borrowed.get() + 1);\n",
        "",
        "evict_control_refuses_in_the_reference_order",
    ),
    (
        "a missing persistent handle is HANDLE even with no free slot",
        "src/tpm.rs",
        "                if self.slots_full() {\n                    return Err(Warn::ObjectMemory.into());\n                }\n                let l = self\n",
        "                let l = self\n",
        "evict_control_refuses_in_the_reference_order",
    ),
    (
        "a NULL-hierarchy object can be made persistent",
        "src/tpm.rs",
        "        if o.hierarchy == Hierarchy::Null || o.public.attributes.st_clear() {",
        "        if o.public.attributes.st_clear() {",
        "evict_control_refuses_in_the_reference_order",
    ),
    (
        "a persistent object can be evicted to another handle",
        "src/tpm.rs",
        "        if evicted && target.handle() != persistent {",
        "        if false && evicted && target.handle() != persistent {",
        "evict_control_refuses_in_the_reference_order",
    ),
    (
        "the persistent store has no limit",
        "src/tpm.rs",
        "        if self.persistent.evicted.len() == object::MAX_PERSISTENT_OBJECTS {",
        "        if false {",
        "evict_control_refuses_in_the_reference_order",
    ),
    (
        "a persistent object does not survive a reset",
        "src/tpm.rs",
        "        let copy = o.duplicate();\n        self.persistent.evicted.insert(persistent, copy);",
        "        let copy = o.duplicate();\n        self.stage.objects.insert(copy);",
        "a_secret_sealed_under_a_persistent_key_unseals_after_a_reset",
    ),
    (
        "an index that clears at Startup keeps its value",
        "src/nv.rs",
        "            if a.clear_stclear() || (a.orderly() && reset) {",
        "            if a.orderly() && reset {",
        "a_pcrlock_index_extends_like_a_pcr_and_starts_over_at_startup_clear",
    ),
    (
        "an extend starts from the old data of an unwritten index",
        "src/nv.rs",
        "        let old = if a.written() { index.data() } else { &zeros[..index.data.len()] };",
        "        let old = index.data();",
        "a_pcrlock_index_extends_like_a_pcr_and_starts_over_at_startup_clear",
    ),
    (
        "a write to an orderly index leaves the orderly shutdown valid",
        "src/tpm.rs",
        "                if orderly {\n                    self.persistent.orderly = None;\n                }",
        "",
        "a_pcrlock_index_extends_like_a_pcr_and_starts_over_at_startup_clear",
    ),
    (
        "the owner writes an index without OWNERWRITE",
        "src/nv.rs",
        "            NvAuth::Owner => a.owner_write(),",
        "            NvAuth::Owner => true,",
        "an_ordinary_index_holds_what_was_written_under_its_own_password",
    ),
    (
        "the owner reads an index without OWNERREAD",
        "src/nv.rs",
        "            NvAuth::Owner => a.owner_read(),",
        "            NvAuth::Owner => true,",
        "an_ordinary_index_holds_what_was_written_under_its_own_password",
    ),
    (
        "another index may read an index",
        "src/nv.rs",
        "            NvAuth::Index => true,\n            NvAuth::OtherIndex => false,\n        };\n        if !allowed {\n            return Err(Fmt0::NvAuthorization.into());\n        }\n        if !a.written()",
        "            NvAuth::Index | NvAuth::OtherIndex => true,\n        };\n        if !allowed {\n            return Err(Fmt0::NvAuthorization.into());\n        }\n        if !a.written()",
        "an_ordinary_index_holds_what_was_written_under_its_own_password",
    ),
    (
        "an unwritten index reads",
        "src/nv.rs",
        "        if !a.written() {\n            return Err(Fmt0::NvUninitialized.into());",
        "        if false {\n            return Err(Fmt0::NvUninitialized.into());",
        "a_pcrlock_index_extends_like_a_pcr_and_starts_over_at_startup_clear",
    ),
    (
        "an index's authValue authorizes without AUTHREAD or AUTHWRITE",
        "src/tpm.rs",
        "            value_available,\n        };",
        "            value_available: true,\n        };",
        "an_ordinary_index_holds_what_was_written_under_its_own_password",
    ),
    (
        "an NV range may run past the index",
        "src/nv.rs",
        "    if len > data_size - offset {",
        "    if len > data_size.saturating_sub(offset) + 1 {",
        "kani:an_nv_range_is_inside_the_index_or_refused",
    ),
    (
        "an NV public area may name any handle",
        "src/nv.rs",
        "        if handle_type(index) != ht::NV_INDEX {\n            return Err(Fmt1::Value);",
        "        if false {\n            return Err(Fmt1::Value);",
        "nv_define_space_refuses_in_the_reference_order",
    ),
    (
        "the owner may define the platform's index",
        "src/nv.rs",
        "        if attrs.platform_create() != platform {",
        "        if attrs.platform_create() && !platform && false {",
        "nv_define_space_refuses_in_the_reference_order",
    ),
    (
        "an index nobody can read may be defined",
        "src/nv.rs",
        "        if !readable || !writable {",
        "        if !writable {",
        "nv_define_space_refuses_in_the_reference_order",
    ),
    (
        "an extend index may be any size",
        "src/nv.rs",
        "            NvType::Extend => usize::from(public.data_size) == digest,",
        "            NvType::Extend => true,",
        "nv_define_space_refuses_in_the_reference_order",
    ),
    (
        "the NV store has no limit",
        "src/nv.rs",
        "        if self.indexes.len() == MAX_NV_INDEXES {",
        "        if false {",
        "nv_define_space_refuses_in_the_reference_order",
    ),
    (
        "the RSA code draws straight from a platform that may repeat itself",
        "src/crypto.rs",
        "    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {\n        self.0.fill(dst);",
        "    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {\n        dst.fill(0);",
        "rsa_signs_and_decrypts_even_when_the_platform_gives_only_zeros",
    ),
    (
        "a protected entity's failure is not counted",
        'src/session.rs',
        '                self.failed_tries = self.failed_tries.saturating_add(1);',
        '                self.failed_tries = self.failed_tries.saturating_add(0);',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'protected entities lock out one failure late',
        'src/session.rs',
        '{ self.failed_tries >= self.max_tries }',
        '{ self.failed_tries > self.max_tries }',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'failures never heal',
        'src/session.rs',
        '                let healed = time.saturating_sub(self.self_heal_timer)\n',
        '                let healed = 0 * time.saturating_sub(self.self_heal_timer)\n',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'a failure does not restart the healing',
        'src/session.rs',
        '            self.self_heal_timer = self.now;\n',
        '',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        "an exempt entity's wrong password counts",
        'src/session.rs',
        '                if auth.da == Da::Exempt {\n                    return Err(Rc::Fmt1(Fmt1::BadAuth, Some(at)));',
        '                if false {\n                    return Err(Rc::Fmt1(Fmt1::BadAuth, Some(at)));',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'DictionaryAttackLockReset clears nothing',
        'src/session.rs',
        '    pub fn reset(&mut self) {\n        self.failed_tries = 0;',
        '    pub fn reset(&mut self) {\n        self.failed_tries += 0;',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'inLockout is reported in the wrong bit',
        'src/capability.rs',
        '((v.in_lockout as u32) << 9)',
        '((v.in_lockout as u32) << 8)',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'a Startup after no orderly shutdown counts nothing',
        'src/session.rs',
        'self.failed_tries < self.max_tries && !orderly {',
        'self.failed_tries < self.max_tries && false {',
        'a_startup_after_no_orderly_shutdown_counts_a_failure',
    ),
    (
        "a new TPM's first Startup counts a failure",
        'src/tpm.rs',
        '            orderly: Some(Orderly::Clear),\n        };',
        '            orderly: None,\n        };',
        'protected_entities_lock_out_after_three_failures_and_heal_with_time',
    ),
    (
        'the lockout hierarchy recovers a moment late',
        'src/session.rs',
        '/ 1000 >= u64::from(self.lockout_recovery)',
        '/ 1000 > u64::from(self.lockout_recovery)',
        'a_failed_lockout_authorization_recovers_after_lockout_recovery',
    ),
    (
        'lockout recovery 0 never recovers at Startup',
        'src/session.rs',
        '        if self.lockout_recovery == 0 {\n            self.lockout_auth_enabled = true;',
        '        if false {\n            self.lockout_auth_enabled = true;',
        'a_failed_lockout_authorization_recovers_after_lockout_recovery',
    ),
    (
        'the DA commands take any hierarchy',
        'src/tpm.rs',
        '        Some(HierarchyAuth::Lockout) => Ok(HierarchyAuth::Lockout),\n        _ =>',
        '        Some(h) => Ok(h),\n        None =>',
        'dictionary_attack_parameters_set_the_limits',
    ),
    (
        "a bound session's failure is not counted",
        'src/session.rs',
        '                lockout.register_failure(core.lockout_bound);\n',
        '',
        'a_session_bound_to_a_protected_key_counts_its_failures_and_locks_out',
    ),
    (
        'a bound session is used in lockout',
        'src/session.rs',
        '            if core.da_bound && lockout.locked_out(core.lockout_bound) {\n                return Err(Warn::Lockout.into());\n            }\n            if !e.attributes',
        '            if false && lockout.locked_out(core.lockout_bound) {\n                return Err(Warn::Lockout.into());\n            }\n            if !e.attributes',
        'a_session_bound_to_a_protected_key_counts_its_failures_and_locks_out',
    ),
    (
        'a self-test ignores a wrong answer',
        'src/selftest.rs',
        '                SelfTests::Run => check(*f, v, platform),',
        '                SelfTests::Run => true,',
        'a_wrong_answer_is_the_failure_and_stops_the_testing',
    ),
    (
        'a self-test does not compare the ECDH secret',
        'src/selftest.rs',
        '                && k.ecdh(&peer)[..] == hex(v.ecdh_zx)[..]',
        '',
        'a_wrong_expected_answer_fails_its_family',
    ),
    (
        'a full self-test tests only what is left',
        'src/selftest.rs',
        '        if full {',
        '        if false {',
        'self_test_tests_what_is_left_or_everything_again',
    ),
    (
        'failure mode answers like a running TPM',
        'src/tpm.rs',
        '        if let Some(Lifecycle::Failure(t)) = &self.lifecycle {\n            return Ok(selftest::failure_answer(t.stage.failed, bytes));\n        }\n',
        '',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
    (
        'a command runs untested cryptography',
        'src/tpm.rs',
        '            Lifecycle::Running(t) if cmd.cc != Cc::Startup => {\n                t.to_test.test(families, &mut self.platform);',
        '            Lifecycle::Running(t) if cmd.cc != Cc::Startup => {\n                let _ = families;',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
    (
        'Startup runs untested hashing',
        'src/tpm.rs',
        '            Lifecycle::Initialized(t) if cmd.cc == Cc::Startup => {\n                t.to_test.test(families, &mut self.platform);',
        '            Lifecycle::Initialized(t) if cmd.cc == Cc::Startup => {\n                let _ = families;',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
    (
        'a _TPM_Init does not test again',
        'src/tpm.rs',
        '        next.to_test = ToTest::ALL;\n',
        '',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
    (
        'failure mode loses what a Resume needs',
        'src/tpm.rs',
        '        let stage = Failure { failed, carried: stage.carried };',
        '        let stage = Failure { failed, carried: stage.carried.and(None) };',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
    (
        'failure mode lists a property for a count of zero',
        'src/selftest.rs',
        '            let one = count > 0 && pt <= TPM_PT_FIRMWARE_VERSION_2;',
        '            let one = pt <= TPM_PT_FIRMWARE_VERSION_2;',
        'a_failed_self_test_answers_only_get_test_result_and_properties_until_init',
    ),
]


def witness(w):
    if w.startswith('kani:'):
        return ['cargo', 'kani', '--harness', w[5:], '--exact']
    return ['cargo', 'test', '--quiet', w]


def run(argv):
    """The witness's exit code, or None when it ran past `WITNESS_TIMEOUT`. It runs in a
    session of its own, so a timeout kills the test binary cargo started, not only cargo."""
    p = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    try:
        return p.wait(timeout=WITNESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        return None


def main(patterns):
    chosen = [s for s in SABOTAGES if not patterns or any(p in s[0] for p in patterns)]
    bad = []
    for name, path, old, _, _ in chosen:
        n = (ROOT / path).read_text().count(old)
        if n != 1:
            bad.append(f'{name}: {path} has {n} matches for its target')
    if bad:
        sys.exit('\n'.join(bad))
    unproven = []
    for name, path, old, new, w in chosen:
        f = ROOT / path
        clean = f.read_text()
        f.write_text(clean.replace(old, new))
        try:
            code = run(witness(w))
        finally:
            f.write_text(clean)
        verdict = 'TIMEOUT' if code is None else 'RED' if code != 0 else 'SURVIVED'
        print(f'{verdict:9} {name}  [{w}]', flush=True)
        if verdict != 'RED':
            unproven.append(name)
    if unproven:
        sys.exit(f'{len(unproven)} sabotage(s) survived or timed out')


if __name__ == '__main__':
    main(sys.argv[1:])
