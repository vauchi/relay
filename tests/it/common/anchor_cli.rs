// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Driving the `vauchi-ohttp-anchor` binary as an operator would.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use vauchi_protocol::ohttp_key::{INTERMEDIATE_CERT_BYTES, IntermediateCert};

pub fn anchor_cli(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vauchi-ohttp-anchor"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vauchi-ohttp-anchor");
    // The CLI refuses a bad argument before reading stdin and may already
    // have exited; its exit status, not the write, is the answer.
    if let Err(e) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    child.wait_with_output().unwrap()
}

pub fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn create_anchor() -> (String, String) {
    let created = anchor_cli(&["create"], b"");
    assert_eq!(created.status.code(), Some(0), "{}", stderr_of(&created));
    let seed = stdout_of(&created).trim().to_string();
    let public_key = anchor_cli(&["public-key"], seed.as_bytes());
    assert_eq!(public_key.status.code(), Some(0));
    (seed, stdout_of(&public_key).trim().to_string())
}

pub fn intermediate_key(path: &Path) -> String {
    let made = anchor_cli(&["intermediate-key", path.to_str().unwrap()], b"");
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    stdout_of(&made).trim().to_string()
}

pub fn read_certs(path: &Path) -> Vec<IntermediateCert> {
    std::fs::read(path)
        .unwrap()
        .chunks_exact(INTERMEDIATE_CERT_BYTES)
        .map(|chunk| IntermediateCert::decode(chunk).unwrap())
        .collect()
}
