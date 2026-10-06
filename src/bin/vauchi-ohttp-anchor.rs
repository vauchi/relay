// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ceremony CLI for a relay's OHTTP anchor (#288 plan 4.1, decisions 0.7
//! and 0.12). The anchor seed only ever arrives on stdin — argv is visible
//! to every process on the host — and is held in memory for one signature.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use vauchi_relay::ohttp_signer::{create_intermediate_key, random_signing_key, write_certificates};
use zeroize::Zeroizing;

const USAGE: &str = "\
usage: vauchi-ohttp-anchor <command>

  create
      Print a new anchor seed on stdout, for Vaultwarden; its public key
      goes to stderr.
  public-key
      Read an anchor seed on stdin; print its public key.
  intermediate-key <key-path>
      On the gateway host: create a new intermediate key file, owner-only;
      print its public key.
  sign <intermediate-public-key> <certs-path>
      Read the anchor seed on stdin; write the two overlapping
      certificates for the intermediate key to a new file.
  install <anchor-public-key> <next-key-path> <key-path> <certs-path>
      On the gateway host: read the certificates on stdin; if they are for
      the next key, signed by the anchor and valid now, replace the live
      certificates and move the next key over the live one. Otherwise
      change nothing.

Seeds and keys are 64 hex characters. Only install replaces files, and
only after every check passes.
";

/// Room for a seed and any trailing whitespace; more is not a seed.
const MAX_SEED_INPUT: u64 = 256;
/// A ceremony issues two certificates; a file of more than a few is not one.
const MAX_CERTS_INPUT: u64 = 16 * vauchi_protocol::ohttp_key::INTERMEDIATE_CERT_BYTES as u64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["create"] => create(),
        ["public-key"] => public_key(),
        ["intermediate-key", key_path] => intermediate_key(Path::new(key_path)),
        ["sign", intermediate, certs_path] => sign(intermediate, Path::new(certs_path)),
        ["install", anchor, next_key, key, certs] => install(
            anchor,
            Path::new(next_key),
            Path::new(key),
            Path::new(certs),
        ),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("vauchi-ohttp-anchor: {message}");
            ExitCode::from(1)
        }
    }
}

fn create() -> Result<(), String> {
    let anchor = random_signing_key();
    println!("{}", *Zeroizing::new(hex::encode(anchor.to_bytes())));
    eprintln!(
        "anchor public key (clients pin this): {}\n\
         Store the seed above in Vaultwarden; it is not written anywhere else.",
        hex::encode(anchor.verifying_key().to_bytes())
    );
    Ok(())
}

fn public_key() -> Result<(), String> {
    let anchor = read_anchor_from_stdin()?;
    println!("{}", hex::encode(anchor.verifying_key().to_bytes()));
    Ok(())
}

fn intermediate_key(key_path: &Path) -> Result<(), String> {
    let public_key = create_intermediate_key(key_path).map_err(|e| e.to_string())?;
    println!("{}", hex::encode(public_key));
    Ok(())
}

fn sign(intermediate: &str, certs_path: &Path) -> Result<(), String> {
    let intermediate = parse_public_key(intermediate)?;
    let anchor = read_anchor_from_stdin()?;
    let certs = write_certificates(&anchor, &intermediate, certs_path, unix_now())
        .map_err(|e| e.to_string())?;
    println!(
        "anchor public key: {}",
        hex::encode(anchor.verifying_key().to_bytes())
    );
    for cert in &certs {
        println!(
            "certificate valid {} .. {} (unix seconds)",
            cert.not_before, cert.not_after
        );
    }
    Ok(())
}

fn install(anchor: &str, next_key: &Path, key: &Path, certs_path: &Path) -> Result<(), String> {
    let anchor = parse_public_key(anchor)?;
    let mut certs = Vec::new();
    std::io::stdin()
        .take(MAX_CERTS_INPUT + 1)
        .read_to_end(&mut certs)
        .map_err(|e| format!("cannot read the certificates from stdin: {e}"))?;
    if certs.len() as u64 > MAX_CERTS_INPUT {
        return Err("stdin holds more than a ceremony's certificates".into());
    }
    let not_after = vauchi_relay::ohttp_install::install(
        &anchor,
        next_key,
        key,
        certs_path,
        &certs,
        unix_now(),
    )
    .map_err(|e| e.to_string())?;
    println!("installed; signing until {not_after} (unix seconds) — restart the relay to load it");
    Ok(())
}

fn parse_public_key(hex_key: &str) -> Result<[u8; 32], String> {
    let refused = || "a public key argument is not 64 hex characters of an Ed25519 key";
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_key, &mut bytes).map_err(|_| refused())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| refused())?;
    Ok(bytes)
}

/// The error never repeats the input: a mistyped seed is still most of a
/// seed (DC-05).
fn read_anchor_from_stdin() -> Result<SigningKey, String> {
    let refused = || "stdin is not one anchor seed (64 hex characters)".to_string();
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(MAX_SEED_INPUT)
        .read_to_end(&mut input)
        .map_err(|_| refused())?;
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(input.trim_ascii(), &mut seed[..]).map_err(|_| refused())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
