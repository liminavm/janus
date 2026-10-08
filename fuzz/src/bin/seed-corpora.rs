// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seeds the fuzz corpora from the guest captures in `tests/corpus`. Random bytes almost never
//! form a command, let alone one with a valid session area, so every target starts from what
//! real guests sent.
//!
//!     cargo run --manifest-path fuzz/Cargo.toml --bin seed-corpora     (from the crate root)
//!
//! `execute` gets every distinct command. `sequence` gets each capture as one record stream,
//! with `_TPM_Init` and locality changes where the capture had them. `prepared` gets every
//! distinct command as a one-record stream, and a ContextLoad of each context the prepared TPM
//! saved, which the fuzzer could not otherwise forge. `state` gets the bodies of a new TPM's
//! state file and the prepared TPM's, before and after Shutdown(STATE).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let execute = root.join("fuzz/corpus/execute");
    let sequence = root.join("fuzz/corpus/sequence");
    fs::create_dir_all(&execute).unwrap();
    fs::create_dir_all(&sequence).unwrap();
    let prepared = root.join("fuzz/corpus/prepared");
    fs::create_dir_all(&prepared).unwrap();
    let mut commands = BTreeSet::new();
    let mut captures: Vec<_> = fs::read_dir(root.join("tests/corpus")).unwrap().flatten().collect();
    captures.sort_by_key(|e| e.path());
    for entry in captures {
        let text = fs::read_to_string(entry.path()).unwrap();
        let mut stream = Vec::new();
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            match v.get("ctrl").and_then(|c| c.as_str()) {
                Some("init") => stream.push(0),
                Some("locality") => stream.push(1 + v["value"].as_u64().unwrap() as u8),
                Some(_) => {}
                None => {
                    let cmd = hex(v["cmd"].as_str().unwrap());
                    stream.push(0xFF);
                    stream.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
                    stream.extend_from_slice(&cmd);
                    commands.insert(cmd);
                }
            }
        }
        let name = entry.path().file_stem().unwrap().to_string_lossy().into_owned();
        fs::write(sequence.join(name), stream).unwrap();
    }
    for (i, cmd) in commands.iter().enumerate() {
        fs::write(execute.join(format!("{i:05}")), cmd).unwrap();
        let mut record = vec![0xFF];
        record.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
        record.extend_from_slice(cmd);
        fs::write(prepared.join(format!("{i:05}")), record).unwrap();
    }
    let (mut tpm, _, contexts) = janus_fuzz::prepared();
    for (i, c) in contexts.iter().enumerate() {
        fs::write(prepared.join(format!("context-{i}")), janus_fuzz::context_load_record(c))
            .unwrap();
    }
    // The prepared TPM's state and snapshot, running and after Shutdown(STATE), and a new
    // TPM's: snapshots of a running TPM hold its loaded key and session.
    let state = root.join("fuzz/corpus/state");
    let snapshot = root.join("fuzz/corpus/snapshot");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&snapshot).unwrap();
    let new = janus::Janus::manufacture(janus_fuzz::Fixed::new().0);
    let body = janus_fuzz::state_body;
    fs::write(state.join("manufactured"), body(&new.state())).unwrap();
    fs::write(snapshot.join("manufactured"), body(&new.snapshot())).unwrap();
    fs::write(state.join("running"), body(&tpm.state())).unwrap();
    fs::write(snapshot.join("running"), body(&tpm.snapshot())).unwrap();
    let shutdown_state = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x45, 0, 1];
    tpm.execute(janus::Locality::ZERO, &shutdown_state);
    fs::write(state.join("shutdown-state"), body(&tpm.state())).unwrap();
    tpm.init();
    fs::write(snapshot.join("shutdown-state"), body(&tpm.snapshot())).unwrap();
    println!("{} commands, sequences from every capture", commands.len());
}
