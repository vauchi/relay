// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The relay serves the CDN's content files over OHTTP, so the server that
//! learns which language a client asked for cannot tie it to an IP address
//! (vauchi/private#733 D8, D11; ADR-037 addendum 2026-10-22). It serves only
//! paths in the content tree, caches briefly, and never forwards an
//! arbitrary URL. Integrity stays end to end: clients check the signed
//! manifest and each file's checksum.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vauchi_relay::content_proxy::{ContentProxy, content_action, is_content_path};
use vauchi_relay::padding::pad_content;

const MAX: usize = 64 * 1024;

/// A CDN on localhost answering `status` with `body` and counting requests.
async fn cdn(status: u16, body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    (format!("http://{address}/v1"), requests)
}

// @internal
#[test]
fn only_paths_in_the_content_tree_are_served() {
    for path in [
        "manifest.json",
        "networks.json",
        "themes.json",
        "locales/pt.json",
        "locales/pt-BR.json",
        "help/de.json",
    ] {
        assert!(is_content_path(path), "{path:?} should be served");
    }
    let long = format!("locales/{}.json", "a".repeat(300));
    for path in [
        "",
        "/manifest.json",
        "../manifest.json",
        "locales/../manifest.json",
        "locales/./pt.json",
        "locales//pt.json",
        "https://evil.test/x.json",
        "locales\\pt.json",
        "locales/%2e%2e.json",
        "locales/pt.txt",
        "locales/pt",
        "secrets/key.json",
        "locales/a/b.json",
        "locales/.json",
        "locales/pt.json?x=1",
        "locales/p\0t.json",
        "locales/pт.json",
        long.as_str(),
    ] {
        assert!(!is_content_path(path), "{path:?} must be refused");
    }
}

// @internal
#[tokio::test]
async fn a_content_file_is_fetched_from_the_cdn() {
    let (origin, _) = cdn(200, b"{\"a\":1}".to_vec()).await;
    let proxy = ContentProxy::new(&origin, Duration::from_secs(600), MAX).unwrap();

    let body = proxy.fetch("locales/pt.json").await.unwrap();

    assert_eq!(body.as_slice(), b"{\"a\":1}");
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_file_is_served_from_the_cache_until_it_expires() {
    let (origin, requests) = cdn(200, b"cached".to_vec()).await;
    let proxy = ContentProxy::new(&origin, Duration::from_secs(600), MAX).unwrap();

    proxy.fetch("manifest.json").await.unwrap();
    proxy.fetch("manifest.json").await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1, "within the lifetime");

    tokio::time::advance(Duration::from_secs(601)).await;
    proxy.fetch("manifest.json").await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 2, "after it expired");
}

// @internal
#[tokio::test]
async fn a_refused_path_never_reaches_the_cdn() {
    let (origin, requests) = cdn(200, b"x".to_vec()).await;
    let proxy = ContentProxy::new(&origin, Duration::from_secs(600), MAX).unwrap();

    assert!(proxy.fetch("../etc/passwd").await.is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

// @internal
#[tokio::test]
async fn a_failed_or_oversized_cdn_answer_is_an_error_and_not_cached() {
    let (missing, _) = cdn(404, b"not found".to_vec()).await;
    let proxy = ContentProxy::new(&missing, Duration::from_secs(600), MAX).unwrap();
    assert!(proxy.fetch("locales/pt.json").await.is_err());

    let (huge, requests) = cdn(200, vec![b'x'; MAX + 1]).await;
    let proxy = ContentProxy::new(&huge, Duration::from_secs(600), MAX).unwrap();
    assert!(proxy.fetch("locales/pt.json").await.is_err());
    assert!(proxy.fetch("locales/pt.json").await.is_err());
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "a failure is not cached"
    );
}

// @internal
#[test]
fn an_origin_must_be_an_http_url_with_a_host() {
    for origin in ["https://cdn.vauchi.app/v1", "http://127.0.0.1:8080/v1"] {
        assert!(
            ContentProxy::new(origin, Duration::from_secs(1), MAX).is_ok(),
            "{origin}"
        );
    }
    for origin in [
        "",
        "cdn.vauchi.app/v1",
        "ftp://cdn.vauchi.app",
        "https://",
        "https://u:p@cdn.vauchi.app",
    ] {
        assert!(
            ContentProxy::new(origin, Duration::from_secs(1), MAX).is_err(),
            "{origin}"
        );
    }
}

// @internal
#[tokio::test]
async fn the_content_action_answers_with_the_file_in_base64() {
    use base64::Engine as _;
    let (origin, _) = cdn(200, b"{\"pt\":1}".to_vec()).await;
    let proxy = ContentProxy::new(&origin, Duration::from_secs(600), MAX).unwrap();

    let answer = content_action(Some(&proxy), serde_json::json!({"path": "locales/pt.json"})).await;

    assert_eq!(answer["status"], "ok", "{answer}");
    let body = base64::engine::general_purpose::STANDARD
        .decode(answer["content_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(body, b"{\"pt\":1}");
}

// @internal
#[tokio::test]
async fn the_content_action_refuses_bad_requests_without_detail() {
    let (origin, requests) = cdn(200, b"x".to_vec()).await;
    let proxy = ContentProxy::new(&origin, Duration::from_secs(600), MAX).unwrap();
    for payload in [
        serde_json::json!({}),
        serde_json::json!({"path": 7}),
        serde_json::json!({"path": "../secret"}),
        serde_json::json!({"path": "https://evil.test/x.json"}),
    ] {
        let answer = content_action(Some(&proxy), payload.clone()).await;
        assert_eq!(answer["status"], "error", "{payload}");
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    let answer = content_action(None, serde_json::json!({"path": "manifest.json"})).await;
    assert_eq!(answer["status"], "error");
}

/// The gateway sees response sizes; every locale file must look the same.
// @internal
#[test]
fn content_answers_are_padded_so_their_size_does_not_name_the_file() {
    let portuguese = pad_content(&vec![b'p'; 150_000]);
    let german = pad_content(&vec![b'd'; 200_000]);
    let manifest = pad_content(&vec![b'm'; 3_000]);

    assert_eq!(portuguese.len(), german.len());
    assert_eq!(manifest.len(), 64 * 1024);
}
