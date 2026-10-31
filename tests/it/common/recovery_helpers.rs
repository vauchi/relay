// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery-proof fixtures shaped like Core's sealed `RecoveryProof`: the
//! version byte, the new key, then whatever follows, which in production is
//! the body encrypted to the old key (spec Social Recovery B3). The relay
//! reads only that header; the slot is still SHA-256(old_pk).

#![allow(dead_code)]

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::Router;
use axum::http::StatusCode;
use base64::Engine;
use serde_json::{Value, json};

use super::http_helpers::{post_json, response_json};

pub const PROOF_VERSION: u8 = 3;

pub fn keypair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

pub fn public_key(seed: u8) -> [u8; 32] {
    keypair(seed).public_key().as_ref().try_into().unwrap()
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for part in parts {
        ctx.update(part);
    }
    ctx.finish().as_ref().try_into().unwrap()
}

/// The slot a proof for `old` is stored under: SHA-256(old_pk).
pub fn key_hash(old: u8) -> [u8; 32] {
    sha256(&[&public_key(old)])
}

pub fn key_hash_hex(old: u8) -> String {
    hex::encode(key_hash(old))
}

pub fn proof_bytes(new: u8, tail: &[u8]) -> Vec<u8> {
    let mut proof = vec![PROOF_VERSION];
    proof.extend_from_slice(&public_key(new));
    proof.extend_from_slice(tail);
    proof
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// An upload of `proof` under `key_hash_hex`, signed by `signer` over
/// `"recovery-store" || key_hash || SHA-256(proof) || timestamp_be`.
pub fn signed_upload_of(signer: u8, key_hash_hex: &str, proof: &[u8], timestamp: u64) -> Value {
    let key_hash = hex::decode(key_hash_hex).unwrap();
    let mut message = b"recovery-store".to_vec();
    message.extend_from_slice(&key_hash);
    message.extend_from_slice(&sha256(&[proof]));
    message.extend_from_slice(&timestamp.to_be_bytes());
    json!({
        "key_hash": key_hash_hex,
        "proof_data": b64(proof),
        "owner_pk": hex::encode(public_key(signer)),
        "timestamp": timestamp,
        "signature": hex::encode(keypair(signer).sign(&message).as_ref()),
    })
}

/// The honest upload: a proof from `old` to `new`, signed by `new`.
pub fn recovery_upload(old: u8, new: u8, tail: &[u8]) -> Value {
    signed_upload_of(new, &key_hash_hex(old), &proof_bytes(new, tail), unix_now())
}

pub fn unsigned_upload(old: u8, new: u8, tail: &[u8]) -> Value {
    json!({
        "key_hash": key_hash_hex(old),
        "proof_data": b64(&proof_bytes(new, tail)),
    })
}

pub async fn store(app: &Router, body: &Value) -> StatusCode {
    post_json(app, "/v2/recovery/store", body).await.status()
}

pub async fn query(app: &Router, key_hashes: &[String]) -> Vec<Value> {
    let resp = post_json(
        app,
        "/v2/recovery/query",
        &json!({ "key_hashes": key_hashes }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    response_json(resp).await["proofs"]
        .as_array()
        .expect("proofs is an array")
        .clone()
}

pub fn proof_data_of(entry: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(entry["proof_data"].as_str().unwrap())
        .unwrap()
}
