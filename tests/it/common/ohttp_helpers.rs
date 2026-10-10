// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP helpers for the API tests: a gateway that signs its keys, and the
//! client side of one encapsulated request.

use std::sync::Arc;

use axum::Router;
use tower::ServiceExt;
use vauchi_relay::ohttp_gateway::OhttpGateway;

use super::http_helpers::{ax_body::Body, ax_http, ax_http::Request, ax_response::Response};

/// A windowed gateway that signs its keys under its own anchor, as a
/// relay without a configured anchor does (ADR-074): clients only ever
/// read the signed record (#288).
#[allow(dead_code)]
pub fn signed_test_gateway() -> OhttpGateway {
    let dir = tempfile::tempdir().unwrap().keep();
    let clock = Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let mut gw = OhttpGateway::windowed(&dir.join("seeds.bin"), clock)
        .expect("windowed gateway must start in tests");
    gw.self_anchored(&dir.join("anchor"))
        .expect("self-anchoring must succeed in tests");
    gw
}

/// Helper: fetch the gateway's signed key record.
#[allow(dead_code)]
pub async fn get_ohttp_key_signed(app: &Router) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v2/ohttp-key-signed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: post raw bytes to the OHTTP endpoint.
#[allow(dead_code)]
pub async fn post_ohttp_bytes(app: &Router, body: Vec<u8>) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/ohttp")
                .header("content-type", "message/ohttp-req")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: encapsulate a JSON message in an OHTTP request.
#[allow(dead_code)]
pub fn ohttp_encrypt(
    encoded_key: &[u8],
    inner: &serde_json::Value,
) -> (Vec<u8>, ohttp::ClientResponse) {
    let mut config = ohttp::KeyConfig::decode(encoded_key).unwrap();
    let client = ohttp::ClientRequest::from_config(&mut config).unwrap();
    let plaintext = serde_json::to_vec(inner).unwrap();
    let padded_bytes = vauchi_relay::padding::pad(&plaintext);
    let (enc_req, client_response) = client.encapsulate(&padded_bytes).unwrap();
    (enc_req, client_response)
}

/// Helper: decrypt an OHTTP response.
#[allow(dead_code)]
pub fn ohttp_decrypt(client_response: ohttp::ClientResponse, enc: &[u8]) -> serde_json::Value {
    let plaintext = client_response.decapsulate(enc).unwrap();
    let unpadded = vauchi_relay::padding::unpad(&plaintext).unwrap();
    serde_json::from_slice(&unpadded).unwrap()
}

/// Helper: fetch the gateway's OHTTP key config as bytes.
#[allow(dead_code)]
pub async fn ohttp_key_bytes(app: &Router) -> Vec<u8> {
    let key_resp = get_ohttp_key_signed(app).await;
    assert_eq!(key_resp.status(), ax_http::StatusCode::OK);
    let body = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();
    vauchi_protocol::ohttp_key::SignedKeyConfig::decode(&body)
        .expect("the gateway serves a decodable signed record")
        .key_config
}

/// Helper: send one action through OHTTP and return the decrypted response.
#[allow(dead_code)]
pub async fn send_ohttp_action(
    app: &Router,
    key_bytes: &[u8],
    action: &str,
    mut inner: serde_json::Value,
) -> serde_json::Value {
    inner["version"] = serde_json::json!(2);
    inner["action"] = serde_json::json!(action);
    let (enc_req, client_resp) = ohttp_encrypt(key_bytes, &inner);
    let resp = post_ohttp_bytes(app, enc_req).await;
    assert_eq!(resp.status(), 200);
    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    ohttp_decrypt(client_resp, &enc_resp_bytes)
}
