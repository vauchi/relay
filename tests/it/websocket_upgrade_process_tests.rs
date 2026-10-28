// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A client that still tries a WebSocket gets `426 Upgrade Required` from
//! the running relay, pointing it at the HTTP v2 API.

use std::process::{Child, Command, Stdio};

use crate::common::poll_until;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Relay {
    child: Child,
    _data_dir: tempfile::TempDir,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn send_raw(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request.as_bytes()).await.unwrap();
    // The relay closes right after answering, with our request still unread,
    // so the close can arrive as a reset: keep what was read before it.
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while let Ok(n @ 1..) = stream.read(&mut chunk).await {
        response.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&response).into_owned()
}

// @scenario: relay_transport_security :: WebSocket upgrades are rejected
#[tokio::test]
async fn a_websocket_upgrade_to_the_running_relay_gets_426_and_the_v2_api() {
    let (main_port, api_port) = (free_port(), free_port());
    let data_dir = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_vauchi-relay"))
        .env("RELAY_LISTEN_ADDR", format!("127.0.0.1:{main_port}"))
        .env("RELAY_METRICS_ADDR", format!("127.0.0.1:{api_port}"))
        .env("RELAY_HTTP_API_ENABLED", "true")
        .env("RELAY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vauchi-relay");
    let _relay = Relay {
        child,
        _data_dir: data_dir,
    };
    let main_addr = format!("127.0.0.1:{main_port}");
    poll_until(
        || {
            let addr = main_addr.clone();
            async move { TcpStream::connect(addr).await.is_ok() }
        },
        15_000,
    )
    .await;

    let response = send_raw(
        &main_addr,
        "GET /ws HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await;

    assert!(
        response.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
        "{response}"
    );
    assert!(response.contains("/v2/"), "{response}");
}
