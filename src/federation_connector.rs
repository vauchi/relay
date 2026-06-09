// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Connector (Initiator Side)
//!
//! Offloads blobs to peer relays over mTLS-HTTP (ADR-052). Federation is
//! request/response: when local storage crosses the offload threshold the
//! relay POSTs `OffloadBlob` envelopes to a peer's
//! `/v2/federation/message` endpoint and acts on the synchronous
//! `OffloadAck` — deleting the local blob and recording a forwarding hint
//! only when the peer confirms `accepted: true`. There is no persistent
//! connection: peers are contacted on demand, authenticated by the mTLS
//! client certificate.

use std::sync::Arc;

use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_http::RELAY_ID_HEADER;
use crate::federation_protocol::{self, FederationEnvelope, FederationPayload};
use crate::forwarding_hints::{ForwardingHint, ForwardingHintStore};
use crate::integrity;
use crate::metrics::RelayMetrics;
use crate::padding;
use crate::storage::BlobStore;

/// TCP connect timeout — prevents 75-second OS-level waits on unreachable hosts.
const TCP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Cap on a peer's response body (the `OffloadAck` envelope is tiny).
const RESPONSE_BODY_LIMIT: usize = 64 * 1024;
/// Blobs offloaded per `check_and_offload` cycle.
const OFFLOAD_BATCH_SIZE: usize = 10;

/// Validates a federation peer URL and resolves it to a connect-ready
/// address, preserving the SSRF defenses of the legacy WebSocket path: the
/// URL is scheme/blocklist-validated and the host is resolved + IP-validated
/// (DNS-rebinding safe) before any connect. Returns the `(host, addr)` to
/// hand to [`send_payload_to_addr`].
async fn validate_and_resolve_peer(
    peer_url: &str,
) -> Result<(String, std::net::SocketAddr), String> {
    crate::url_validation::validate_federation_url(peer_url)
        .map_err(|e| format!("SSRF validation failed for {peer_url}: {e}"))?;

    let stripped = peer_url
        .strip_prefix("https://")
        .ok_or_else(|| "Federation peer URL must use https:// (mTLS-only, ADR-052)".to_string())?;
    let authority = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| "Invalid port in peer URL".to_string())?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), 443u16)
    };

    let addr = crate::url_validation::resolve_and_validate(&host, port)
        .await
        .map_err(|e| format!("SSRF: {e}"))?;
    Ok((host, addr))
}

/// Sends a federation envelope to an already-SSRF-validated peer address
/// over mTLS-HTTP and returns the peer's response payload.
///
/// `addr` MUST be the output of [`validate_and_resolve_peer`] - this function
/// connects to it directly, so passing an unvalidated address bypasses the
/// SSRF guard. Peer authenticity rests on the mTLS client certificate;
/// `own_relay_id` is declared in the `X-Federation-Relay-Id` header (the HTTP
/// analogue of the WS handshake). The split keeps the connect/send transport
/// independently testable against a loopback peer (SSRF blocks loopback URLs).
pub async fn send_payload_to_addr(
    host: &str,
    addr: std::net::SocketAddr,
    own_relay_id: &str,
    client_config: &Arc<ClientConfig>,
    envelope: &FederationEnvelope,
) -> Result<FederationPayload, String> {
    let tcp_stream = timeout(TCP_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "TCP connect timed out".to_string())?
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let connector = TlsConnector::from(client_config.clone());
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("Invalid server name: {e}"))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("mTLS handshake failed: {e}"))?;

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("HTTP handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body = serde_json::to_vec(envelope).map_err(|e| format!("encode envelope: {e}"))?;
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v2/federation/message")
        .header("host", host)
        .header("content-type", "application/json")
        .header(RELAY_ID_HEADER, own_relay_id)
        .body(axum::body::Body::from(body))
        .map_err(|e| format!("build request: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("POST failed: {e}"))?;
    if response.status() != hyper::StatusCode::OK {
        return Err(format!("peer returned status {}", response.status()));
    }

    let bytes = axum::body::to_bytes(
        axum::body::Body::new(response.into_body()),
        RESPONSE_BODY_LIMIT,
    )
    .await
    .map_err(|e| format!("read response: {e}"))?;
    let resp_envelope: FederationEnvelope =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode response: {e}"))?;
    Ok(resp_envelope.payload)
}

/// POSTs a federation envelope to a peer's `/v2/federation/message` endpoint
/// over mTLS-HTTP and returns the peer's response payload. Composes
/// [`validate_and_resolve_peer`] (SSRF guard) with [`send_payload_to_addr`].
async fn post_federation_message(
    peer_url: &str,
    own_relay_id: &str,
    client_config: &Arc<ClientConfig>,
    envelope: &FederationEnvelope,
) -> Result<FederationPayload, String> {
    let (host, addr) = validate_and_resolve_peer(peer_url).await?;
    send_payload_to_addr(&host, addr, own_relay_id, client_config, envelope).await
}

/// Manages offloading blobs to federation peers when storage exceeds the
/// configured threshold.
///
/// A blob is deleted from local storage only after the peer confirms
/// receipt with `OffloadAck { accepted: true }` — a rejected or failed
/// offload leaves the blob in place to retry on the next cycle, so no data
/// is lost if a peer is full or unreachable.
pub struct OffloadManager {
    pub storage: Arc<dyn BlobStore>,
    pub hint_store: Arc<dyn ForwardingHintStore>,
    pub config: Arc<RelayConfig>,
    pub metrics: RelayMetrics,
    /// mTLS client config for connecting to peers. `None` disables
    /// offloading (federation is mTLS-only, ADR-052).
    pub tls_client_config: Option<Arc<ClientConfig>>,
}

impl OffloadManager {
    /// Checks storage usage and offloads the oldest blobs to a peer if
    /// above threshold. Returns the number of blobs the peer accepted (and
    /// that were therefore deleted locally).
    pub async fn check_and_offload(&self) -> usize {
        let used = self.storage.storage_size_bytes();
        let ratio = used as f64 / self.config.storage.max_storage_bytes as f64;
        if ratio < self.config.federation.offload_threshold {
            return 0;
        }

        let client_config = match &self.tls_client_config {
            Some(c) => c,
            None => {
                debug!("Federation mTLS not configured; cannot offload");
                return 0;
            }
        };
        let peer_url = match self.config.federation.peers.first() {
            Some(url) => url,
            None => {
                debug!("No federation peers configured for offload");
                return 0;
            }
        };

        let own_relay_id = &self.config.federation.relay_id;
        let candidates = self.storage.get_oldest_blobs(OFFLOAD_BATCH_SIZE);

        let mut sent = 0;
        for (routing_id, blob) in candidates {
            // Pad to a fixed bucket size to resist traffic analysis; the
            // integrity hash covers the padded bytes, as the peer verifies.
            let padded_data = padding::pad(&blob.data);
            let integrity_hash = integrity::compute_integrity_hash(&padded_data);
            let envelope =
                federation_protocol::create_federation_envelope(FederationPayload::OffloadBlob {
                    blob_id: blob.id.clone(),
                    routing_id: routing_id.clone(),
                    data: padded_data,
                    created_at_secs: blob.created_at_secs,
                    integrity_hash,
                    hop_count: blob.hop_count,
                });

            match post_federation_message(peer_url, own_relay_id, client_config, &envelope).await {
                Ok(FederationPayload::OffloadAck { accepted: true, .. }) => {
                    if self.storage.remove_blob(&blob.id) {
                        self.hint_store.store_hint(ForwardingHint {
                            routing_id,
                            blob_id: blob.id.clone(),
                            target_relay: peer_url.clone(),
                            created_at_secs: blob.created_at_secs,
                            expires_at_secs: blob.created_at_secs
                                + self.config.storage.blob_ttl_secs,
                        });
                        self.metrics.federation_hints_stored.inc();
                        self.metrics.federation_hints_active.inc();
                        debug!("Offload confirmed: blob {} deleted locally", blob.id);
                    }
                    self.metrics.federation_offloads_sent.inc();
                    sent += 1;
                }
                Ok(FederationPayload::OffloadAck {
                    accepted: false,
                    reason,
                    ..
                }) => {
                    // Peer refused (e.g. at capacity) — keep the blob and stop
                    // hammering this peer for the rest of the batch.
                    warn!("Peer rejected offload ({reason:?}); keeping blob locally");
                    break;
                }
                Ok(other) => {
                    warn!("Unexpected federation response to offload: {other:?}");
                    break;
                }
                Err(e) => {
                    warn!("Offload to peer failed: {e}");
                    break;
                }
            }
        }

        if sent > 0 {
            info!("Offloaded {sent} blobs to peer relay");
        }
        sent
    }
}

// INLINE_TEST_REQUIRED: exercises private offload internals against an
// in-memory store; the real mTLS round-trip is covered by the integration
// test `federation_connector_offloads_over_real_mtls` in tests/it.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding_hints::SqliteForwardingHintStore;
    use crate::storage::{SqliteBlobStore, StoredBlob};

    fn make_test_config(max_storage: usize, threshold: f64) -> Arc<RelayConfig> {
        use crate::config::{FederationConfig, StorageConfig};
        Arc::new(RelayConfig {
            storage: StorageConfig {
                max_storage_bytes: max_storage,
                ..Default::default()
            },
            federation: FederationConfig {
                offload_threshold: threshold,
                offload_refuse: 0.95,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn manager(config: Arc<RelayConfig>, tls: Option<Arc<ClientConfig>>) -> OffloadManager {
        OffloadManager {
            storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
            hint_store: Arc::new(SqliteForwardingHintStore::in_memory().unwrap()),
            config,
            metrics: RelayMetrics::new(),
            tls_client_config: tls,
        }
    }

    // @internal
    #[tokio::test]
    async fn test_offload_below_threshold_is_noop() {
        let config = make_test_config(1_000_000, 0.80);
        let mgr = manager(config, None);
        // Well below 80% of 1 MB — no offload attempted (no TLS needed).
        mgr.storage.store("r1", StoredBlob::new(vec![1; 100]));
        assert_eq!(mgr.check_and_offload().await, 0);
        assert_eq!(mgr.hint_store.hint_count(), 0);
    }

    // @internal
    #[tokio::test]
    async fn test_offload_above_threshold_without_tls_is_noop() {
        // Over threshold but mTLS unconfigured: federation is mTLS-only, so
        // nothing is offloaded and the blob stays put.
        let config = make_test_config(100, 0.01);
        let mgr = manager(config, None);
        mgr.storage.store("r1", StoredBlob::new(vec![1; 50]));
        assert_eq!(mgr.check_and_offload().await, 0);
    }

    // @internal
    #[tokio::test]
    async fn test_offload_to_loopback_peer_is_ssrf_blocked_and_keeps_blob() {
        use crate::config::{FederationConfig, StorageConfig};
        let config = Arc::new(RelayConfig {
            storage: StorageConfig {
                max_storage_bytes: 100,
                ..Default::default()
            },
            federation: FederationConfig {
                offload_threshold: 0.01,
                offload_refuse: 0.95,
                relay_id: "self".to_string(),
                peers: vec!["https://127.0.0.1:9".to_string()],
                ..Default::default()
            },
            ..Default::default()
        });
        // Any client config: SSRF rejects the loopback peer before TLS.
        let tls = Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let mgr = manager(config, Some(tls));
        mgr.storage.store("r1", StoredBlob::new(vec![1; 50]));

        assert_eq!(
            mgr.check_and_offload().await,
            0,
            "SSRF must block the loopback peer"
        );
        // No data loss: a failed offload leaves the blob in local storage.
        assert_eq!(
            mgr.storage.get_oldest_blobs(10).len(),
            1,
            "blob must be kept when offload fails"
        );
    }
}
