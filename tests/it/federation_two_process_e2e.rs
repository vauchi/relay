// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! True two-process federation e2e: boots two real `vauchi-relay` OS
//! processes (A and B) wired as mTLS-HTTP peers, sends a blob to A, and
//! asserts it federates to B over the wire (ADR-052).
//!
//! Local federation means A connects to B on loopback, which the SSRF guard
//! blocks. A is therefore launched with the debug-only escape
//! `RELAY_FEDERATION_DANGEROUSLY_ALLOW_LOOPBACK` (honored only in
//! `debug_assertions` builds — the integration-test binary is one; release is
//! not). The v2 API (`/v2/send`) and Prometheus `/metrics` are both served on
//! `RELAY_METRICS_ADDR`; verification reads the federation counters there, so
//! it does not depend on mailbox-token fetch semantics.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::common::mtls::generate_mtls_certs;
use crate::common::poll_until;
use tokio::net::TcpStream;

/// A spawned relay process plus the addresses the test talks to. Killed on
/// drop so a panicking test never leaks processes.
struct RelayProcess {
    child: Child,
    /// Serves both the v2 API (`/v2/*`) and `/metrics` (`RELAY_METRICS_ADDR`).
    api_addr: SocketAddr,
    fed_addr: SocketAddr,
    log_path: PathBuf,
    _data_dir: tempfile::TempDir,
}

impl RelayProcess {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reserves a free loopback port by binding to `:0` and dropping the listener.
/// A small race remains (the port could be taken before the child binds); the
/// readiness poll absorbs it by failing the test with a clear message.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn loopback(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Spawns a relay with federation + mTLS + the v2 API enabled. `peer` is the
/// federation URL this relay offloads to (`None` for a pure receiver). The
/// child's stderr (relay logs) is captured to a file for failure diagnostics.
fn spawn_relay(cert: &str, key: &str, ca: &str, peer: Option<&str>) -> RelayProcess {
    // RELAY_LISTEN_ADDR must be unique per relay (else both default to :8080).
    let (main_port, api_port, fed_port) = (free_port(), free_port(), free_port());
    let data_dir = tempfile::tempdir().unwrap();
    let log_path = data_dir.path().join("relay.stderr.log");
    let log_file = std::fs::File::create(&log_path).unwrap();
    let log_file_err = log_file.try_clone().unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vauchi-relay"));
    cmd.env("RELAY_LISTEN_ADDR", format!("127.0.0.1:{main_port}"))
        .env("RELAY_METRICS_ADDR", format!("127.0.0.1:{api_port}"))
        .env(
            "RELAY_FEDERATION_MTLS_ADDR",
            format!("127.0.0.1:{fed_port}"),
        )
        .env("RELAY_HTTP_API_ENABLED", "true")
        .env("RELAY_DATA_DIR", data_dir.path())
        .env("RELAY_FEDERATION_ENABLED", "true")
        .env("RELAY_FEDERATION_TLS_CERT", cert)
        .env("RELAY_FEDERATION_TLS_KEY", key)
        .env("RELAY_FEDERATION_TLS_CA", ca)
        // storage_size_bytes() is the whole SQLite file (page_count*page_size),
        // tens of KB even when empty — so max must comfortably exceed that. With
        // threshold 0.0 A always attempts to offload; refuse 0.99 leaves B (near
        // empty) accepting.
        .env("RELAY_MAX_STORAGE_BYTES", "50000000")
        .env("RELAY_MAX_STORAGE_PER_USER", "1000000")
        .env("RELAY_MAX_BLOBS_PER_USER", "1000")
        .env("RELAY_FEDERATION_OFFLOAD_THRESHOLD", "0.0")
        .env("RELAY_FEDERATION_OFFLOAD_REFUSE", "0.99")
        .env("RELAY_FEDERATION_CAPACITY_INTERVAL", "1")
        .env("RUST_LOG", "warn,vauchi_relay=debug")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));
    if let Some(p) = peer {
        cmd.env("RELAY_FEDERATION_PEERS", p)
            .env("RELAY_FEDERATION_DANGEROUSLY_ALLOW_LOOPBACK", "1");
    }

    let child = cmd.spawn().expect("spawn vauchi-relay");
    RelayProcess {
        child,
        api_addr: loopback(api_port),
        fed_addr: loopback(fed_port),
        log_path,
        _data_dir: data_dir,
    }
}

/// Minimal plaintext HTTP/1 request to a loopback relay listener, over hyper
/// (no TLS — the federation hop is the relay's own mTLS, not the test's).
async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    json_body: Option<String>,
) -> Result<(u16, String), String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    let request = match json_body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body)),
        None => builder.body(axum::body::Body::empty()),
    }
    .map_err(|e| format!("build request: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(axum::body::Body::new(response.into_body()), 1 << 20)
        .await
        .map_err(|e| format!("read body: {e}"))?;
    Ok((status, String::from_utf8_lossy(&bytes).to_string()))
}

/// Parses a bare Prometheus counter (`name <value>`, no labels) from the text
/// exposition. Returns `None` if absent.
fn metric_value(text: &str, name: &str) -> Option<f64> {
    text.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let rest = l.strip_prefix(name)?;
        if !rest.starts_with(' ') {
            return None; // guards against `<name>_suffix` collisions
        }
        rest.trim().parse().ok()
    })
}

/// Polls the relay's `/metrics` until it serves 200 — proves the API+metrics
/// listener is up.
async fn wait_until_ready(relay: &RelayProcess) {
    let addr = relay.api_addr;
    poll_until(
        || async move {
            matches!(
                http_request(addr, "GET", "/metrics", None).await,
                Ok((200, _))
            )
        },
        15_000,
    )
    .await;
}

async fn counter(api_addr: SocketAddr, name: &str) -> f64 {
    match http_request(api_addr, "GET", "/metrics", None).await {
        Ok((200, body)) => metric_value(&body, name).unwrap_or(0.0),
        _ => 0.0,
    }
}

// @internal
#[tokio::test]
async fn blob_federates_across_two_relay_processes() {
    let (ca_file, cert_file, key_file) = generate_mtls_certs();
    let (ca, cert, key) = (
        ca_file.path().to_str().unwrap(),
        cert_file.path().to_str().unwrap(),
        key_file.path().to_str().unwrap(),
    );

    // B is the receiver; A offloads to B. Spawn B first so its mTLS listener is
    // up by the time A's offload loop fires (A retries each interval anyway).
    let relay_b = spawn_relay(cert, key, ca, None);
    let peer_url = format!("https://localhost:{}", relay_b.fed_addr.port());
    let relay_a = spawn_relay(cert, key, ca, Some(&peer_url));

    wait_until_ready(&relay_b).await;
    wait_until_ready(&relay_a).await;

    // Seed A above its offload threshold. recipient_id is 64 hex; ciphertext is
    // valid base64 (`A`*2000 decodes to 1500 bytes > 0.1 * 4096).
    let recipient_id = "ab".repeat(32);
    let ciphertext = "A".repeat(2000);
    let body = format!(r#"{{"recipient_id":"{recipient_id}","ciphertext":"{ciphertext}"}}"#);
    let (status, send_body) = http_request(relay_a.api_addr, "POST", "/v2/send", Some(body))
        .await
        .expect("POST /v2/send to relay A");
    assert_eq!(status, 200, "send to A must succeed, got body: {send_body}");

    // A's offload loop (1s interval) should ship the blob to B over mTLS-HTTP.
    // Poll B's received counter; on timeout, dump both relays' logs.
    let recv_counter = "relay_federation_offloads_received_total";
    let mut received = 0.0;
    for _ in 0..150 {
        received = counter(relay_b.api_addr, recv_counter).await;
        if received >= 1.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        received >= 1.0,
        "relay B never received the offloaded blob.\n=== relay A log ===\n{}\n=== relay B log ===\n{}",
        relay_a.log(),
        relay_b.log(),
    );

    // CC-03: assert exact counter values on both ends of the federation hop.
    assert_eq!(
        counter(relay_a.api_addr, "relay_federation_offloads_sent_total").await,
        1.0,
        "relay A must record exactly one sent offload"
    );
}
