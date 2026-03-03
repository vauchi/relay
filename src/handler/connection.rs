// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket connection lifecycle: handshake, pending delivery, and message loop.

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, warn};

use super::messages::handle_message;
use super::nonce::validate_client_id;
use super::types::{ConnectionDeps, HandleResult, HandlerResponse, MessageContext};
use super::verify::{protocol, verify_signed_handshake};
use crate::connection_registry::RegistryMessage;
use crate::noise_transport::{self, NoiseResponder, NoiseTransport};

/// Performs the WebSocket + Noise handshake, returning the parsed handshake data.
///
/// Reads the first WebSocket message, negotiates Noise NK if requested,
/// decodes and validates the protocol-level Handshake, and sends the HandshakeAck.
///
/// Returns `(client_id, device_id, routing_id, suppress_presence, noise_session)` on success,
/// or `None` if the handshake failed (connection is dropped).
#[allow(clippy::type_complexity)]
async fn perform_handshake(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    read: &mut futures_util::stream::SplitStream<WebSocketStream<TcpStream>>,
    deps: &ConnectionDeps,
    session: &str,
) -> Option<(String, Option<String>, String, bool, Option<NoiseTransport>)> {
    // Read the first WebSocket message — could be v1 Handshake or v2 Noise handshake
    let first_msg = match timeout(deps.idle_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => data,
        Ok(Some(Ok(_))) => {
            warn!("[{}] Expected binary message for handshake", session);
            return None;
        }
        Ok(Some(Err(e))) => {
            warn!("[{}] Error reading handshake: {}", session, e);
            return None;
        }
        Ok(None) => {
            debug!("[{}] Connection closed before handshake", session);
            return None;
        }
        Err(_) => {
            warn!("[{}] Handshake timeout (slowloris protection)", session);
            return None;
        }
    };

    // Detect v2 (Noise) or v1 (plaintext) connection
    let mut noise_session: Option<NoiseTransport> = None;

    let handshake_data = if noise_transport::is_noise_v2_handshake(&first_msg) {
        // --- v2 Noise NK handshake ---
        let noise_key = match deps.noise_static_key {
            Some(key) => key,
            None => {
                warn!(
                    "[{}] v2 handshake received but Noise is not configured",
                    session
                );
                return None;
            }
        };

        // Extract handshake bytes (skip 3-byte magic)
        let handshake_bytes = &first_msg[noise_transport::V2_MAGIC.len()..];

        // Process NK handshake (-> e, es)
        let responder = match NoiseResponder::new(&noise_key) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Failed to create Noise responder: {}", session, e);
                return None;
            }
        };

        let (transport, response) = match responder.process_handshake(handshake_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Noise handshake failed: {}", session, e);
                return None;
            }
        };

        // Send NK response (<- e, ee) with V2 magic prefix
        let mut response_msg = Vec::with_capacity(noise_transport::V2_MAGIC.len() + response.len());
        response_msg.extend_from_slice(&noise_transport::V2_MAGIC);
        response_msg.extend_from_slice(&response);
        if write.send(Message::Binary(response_msg)).await.is_err() {
            warn!("[{}] Failed to send Noise handshake response", session);
            return None;
        }

        noise_session = Some(transport);

        debug!("[{}] Noise NK handshake completed", session);

        // Read the next message — the encrypted Handshake
        match timeout(deps.idle_timeout, read.next()).await {
            Ok(Some(Ok(Message::Binary(encrypted_data)))) => {
                match noise_session.as_mut().unwrap().decrypt(&encrypted_data) {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        warn!("[{}] Failed to decrypt Handshake: {}", session, e);
                        return None;
                    }
                }
            }
            _ => {
                warn!(
                    "[{}] Expected encrypted Handshake after Noise setup",
                    session
                );
                return None;
            }
        }
    } else {
        // --- v1 plaintext connection ---
        if deps.require_noise_encryption {
            warn!(
                "[{}] Plaintext connection rejected (require_noise_encryption=true)",
                session
            );
            return None;
        }
        first_msg
    };

    // Parse the Handshake message (same for v1 and v2)
    let (client_id, device_id, routing_token, suppress_presence, client_supported_versions) =
        match protocol::decode_message(&handshake_data) {
            Ok(envelope) => {
                if let protocol::MessagePayload::Handshake(hs) = envelope.payload {
                    // Validate client_id format
                    if !validate_client_id(&hs.client_id) {
                        warn!("[{}] Invalid client_id format", session);
                        return None;
                    }
                    // Validate device_id format if present
                    if let Some(ref did) = hs.device_id {
                        if !validate_client_id(did) {
                            warn!("[{}] Invalid device_id format", session);
                            return None;
                        }
                    }
                    // Validate routing_token format if present
                    if let Some(ref rt) = hs.routing_token {
                        if !validate_client_id(rt) {
                            warn!("[{}] Invalid routing_token format", session);
                            return None;
                        }
                    }
                    // Verify signed handshake if auth fields are present.
                    if let (Some(ref pk), Some(ref nonce), Some(ref sig), Some(ts)) = (
                        &hs.identity_public_key,
                        &hs.nonce,
                        &hs.signature,
                        hs.timestamp,
                    ) {
                        match verify_signed_handshake(pk, nonce, sig, ts, &deps.nonce_tracker) {
                            Ok(derived_id) => {
                                if derived_id != hs.client_id {
                                    warn!("[{}] Authenticated client_id mismatch", session);
                                    return None;
                                }
                            }
                            Err(reason) => {
                                warn!("[{}] Handshake auth failed: {}", session, reason);
                                return None;
                            }
                        }
                    }
                    (
                        hs.client_id,
                        hs.device_id,
                        hs.routing_token,
                        hs.suppress_presence,
                        hs.supported_versions,
                    )
                } else {
                    warn!(
                        "[{}] Expected Handshake, got {:?}",
                        session, envelope.payload
                    );
                    return None;
                }
            }
            Err(e) => {
                warn!("[{}] Failed to decode handshake: {}", session, e);
                return None;
            }
        };

    // Compute the routing ID: use routing_token if provided, otherwise client_id.
    let routing_id = routing_token.unwrap_or_else(|| client_id.clone());

    debug!(
        "[{}] Client connected (has_device_id: {}, suppress_presence: {}, noise: {})",
        session,
        device_id.is_some(),
        suppress_presence,
        noise_session.is_some()
    );

    // Version negotiation: pick the highest version both sides support.
    // Server currently supports [PROTOCOL_VERSION] only.
    let server_versions = [protocol::PROTOCOL_VERSION];
    let negotiated =
        protocol::negotiate_version(client_supported_versions.as_deref(), &server_versions);
    let negotiated_version = match negotiated {
        Some(v) => v,
        None => {
            warn!(
                "[{}] Version negotiation failed (client: {:?}, server: {:?})",
                session, client_supported_versions, server_versions
            );
            return None;
        }
    };

    // Send HandshakeAck with server version and supported features
    let hs_ack = protocol::create_handshake_ack(noise_session.is_some(), negotiated_version);
    if let Ok(ack_data) = protocol::encode_message(&hs_ack) {
        let send_data = if let Some(ref mut ns) = noise_session {
            match ns.encrypt(&ack_data) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    warn!("[{}] Failed to encrypt HandshakeAck: {}", session, e);
                    return None;
                }
            }
        } else {
            ack_data
        };
        if write.send(Message::Binary(send_data)).await.is_err() {
            warn!("[{}] Failed to send HandshakeAck", session);
            return None;
        }
    }

    Some((
        client_id,
        device_id,
        routing_id,
        suppress_presence,
        noise_session,
    ))
}

/// Delivers pending blobs, forwarding hints, and device sync messages
/// to a newly connected client.
async fn deliver_pending(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    noise_session: &mut Option<NoiseTransport>,
    ctx: &MessageContext<'_>,
) -> bool {
    let deps = ctx.deps;

    // Send any pending blobs for this client and notify senders
    let pending = deps.storage.peek(&ctx.routing_id);
    let pending_blob_ids: Vec<String> = pending.iter().map(|b| b.id.clone()).collect();
    for blob in pending {
        // Apply per-blob delivery jitter for traffic analysis resistance (T2.2, T7.4)
        let jitter = crate::jitter::generate_jitter(
            deps.delivery_jitter_min_ms,
            deps.delivery_jitter_max_ms,
        );
        tokio::time::sleep(jitter).await;

        let envelope = protocol::create_update_delivery(&blob.id, &ctx.routing_id, &blob.data);
        match protocol::encode_message(&envelope) {
            Ok(data) => {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!("[{}] Failed to encrypt pending blob: {}", ctx.session, e);
                            continue;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
                    warn!("[{}] Failed to send pending blob", ctx.session);
                    return false;
                }
            }
            Err(e) => {
                error!("[{}] Failed to encode blob delivery: {}", ctx.session, e);
            }
        }
    }

    // Send Delivered acks to senders for blobs we just delivered.
    // Suppressed when recipient requested suppress_presence.
    if !ctx.suppress_presence {
        for blob_id in &pending_blob_ids {
            let sender_client_id = { deps.blob_sender_map.read().get(blob_id).cloned() };
            if let Some(sender_id) = sender_client_id {
                let ack = protocol::create_ack(blob_id, protocol::AckStatus::Delivered);
                if let Ok(ack_data) = protocol::encode_message(&ack) {
                    deps.registry
                        .try_send(&sender_id, RegistryMessage { data: ack_data });
                }
                deps.blob_sender_map.write().remove(blob_id);
            }
        }
    }

    // Send forwarding hints if federation is enabled and hints exist
    if let Some(ref hint_store) = deps.hint_store {
        let hints = hint_store.get_hints(&ctx.routing_id);
        if !hints.is_empty() {
            let hint_infos: Vec<protocol::ForwardingHintInfo> = hints
                .iter()
                .map(|h| protocol::ForwardingHintInfo {
                    blob_id: h.blob_id.clone(),
                    relay_url: h.target_relay.clone(),
                    expires_at_secs: h.expires_at_secs,
                })
                .collect();
            let hint_envelope = protocol::MessageEnvelope {
                version: protocol::PROTOCOL_VERSION,
                message_id: uuid::Uuid::new_v4().to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                payload: protocol::MessagePayload::ForwardingHints({
                    let unsigned = protocol::ForwardingHints {
                        hints: hint_infos,
                        relay_signing_key: None,
                        signature: None,
                    };
                    // R-M4: Sign forwarding hints with relay's Ed25519 key
                    match &deps.relay_signing_key {
                        Some(key) => key.sign_hints(&unsigned),
                        None => unsigned,
                    }
                }),
            };
            if let Ok(data) = protocol::encode_message(&hint_envelope) {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!(
                                "[{}] Failed to encrypt forwarding hints: {}",
                                ctx.session, e
                            );
                            return false;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
                    warn!("[{}] Failed to send forwarding hints", ctx.session);
                    return false;
                }
            }
            debug!("[{}] Sent {} forwarding hints", ctx.session, hints.len());
        }
    }

    // Send any pending device sync messages if device_id is present
    if let Some(ref did) = ctx.device_id {
        let pending_sync = deps.device_sync_storage.peek(&ctx.client_id, did);
        let pending_count = pending_sync.len();
        for msg in pending_sync {
            let envelope = protocol::create_device_sync_delivery(
                &msg.id,
                &msg.identity_id,
                &msg.target_device_id,
                &msg.sender_device_id,
                &msg.encrypted_payload,
                msg.version,
            );
            match protocol::encode_message(&envelope) {
                Ok(data) => {
                    let send_data = if let Some(ref mut ns) = noise_session {
                        match ns.encrypt(&data) {
                            Ok(encrypted) => encrypted,
                            Err(e) => {
                                error!("[{}] Failed to encrypt device sync: {}", ctx.session, e);
                                continue;
                            }
                        }
                    } else {
                        data
                    };
                    if write.send(Message::Binary(send_data)).await.is_err() {
                        warn!("[{}] Failed to send pending device sync", ctx.session);
                        return false;
                    }
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to encode device sync delivery: {}",
                        ctx.session, e
                    );
                }
            }
        }
        if pending_count > 0 {
            debug!(
                "[{}] Sent {} pending device sync messages",
                ctx.session, pending_count
            );
        }
    }

    true
}

/// Optionally encrypts data via the Noise session, then sends it over WebSocket.
/// Returns `Err` if encryption or sending fails.
async fn noise_encrypt_and_send(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    data: Vec<u8>,
    noise_session: &mut Option<NoiseTransport>,
    session: &str,
) -> Result<(), ()> {
    let send_data = if let Some(ref mut ns) = noise_session {
        match ns.encrypt(&data) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                warn!("[{}] Failed to encrypt outgoing message: {}", session, e);
                return Err(());
            }
        }
    } else {
        data
    };
    write.send(Message::Binary(send_data)).await.map_err(|_| ())
}

/// Processes the responses from a `HandleResult`, sending messages over the
/// WebSocket and forwarding to the registry as needed.
async fn process_handle_result(
    result: HandleResult,
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    noise_session: &mut Option<NoiseTransport>,
    ctx: &MessageContext<'_>,
) {
    for response in result.responses {
        match response {
            HandlerResponse::SendAck { message_id, status } => {
                let ack = protocol::create_ack(&message_id, status);
                if let Ok(ack_data) = protocol::encode_message(&ack) {
                    let _ =
                        noise_encrypt_and_send(write, ack_data, noise_session, ctx.session).await;
                }
            }
            HandlerResponse::SendEnvelope(envelope) => {
                if let Ok(data) = protocol::encode_message(&envelope) {
                    let _ = noise_encrypt_and_send(write, data, noise_session, ctx.session).await;
                }
            }
            HandlerResponse::ForwardToRegistry { target_id, data } => {
                ctx.deps
                    .registry
                    .try_send(&target_id, RegistryMessage { data });
            }
            HandlerResponse::RemoveFromSenderMap(blob_id) => {
                ctx.deps.blob_sender_map.write().remove(&blob_id);
            }
            HandlerResponse::Skip => {
                // No action needed
            }
        }
    }
}

/// Handles a WebSocket connection.
pub async fn handle_connection(ws_stream: WebSocketStream<TcpStream>, deps: ConnectionDeps) {
    // Generate a random session label for logging.
    // The relay must never log client_id (identity fingerprint) to prevent
    // relay operators from identifying users in logs.
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = &session_id[..8];

    let (mut write, mut read) = ws_stream.split();

    // Perform handshake (Noise NK negotiation + protocol Handshake + validation)
    let (client_id, device_id, routing_id, suppress_presence, mut noise_session) =
        match perform_handshake(&mut write, &mut read, &deps, session).await {
            Some(result) => result,
            None => return,
        };

    // Register in connection registry for delivery notifications
    let (conn_id, mut registry_rx) = deps.registry.register(&routing_id);

    // Build the message context shared by all handlers
    let ctx = MessageContext {
        routing_id: routing_id.clone(),
        client_id,
        device_id,
        suppress_presence,
        session,
        deps: &deps,
    };

    // Deliver pending blobs, forwarding hints, and device sync messages
    if !deliver_pending(&mut write, &mut noise_session, &ctx).await {
        deps.registry.unregister(&routing_id, conn_id);
        return;
    }

    // Process incoming messages with idle timeout.
    // Uses select! to multiplex between WebSocket reads and registry messages
    // (delivery notifications from other client handlers).
    loop {
        let msg = tokio::select! {
            // WebSocket message from client
            ws_msg = timeout(deps.idle_timeout, read.next()) => {
                match ws_msg {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        debug!("[{}] Disconnected", session);
                        break;
                    }
                    Err(_) => {
                        warn!("[{}] Idle timeout (slowloris protection)", session);
                        break;
                    }
                }
            }
            // Registry message (delivery notification from another handler)
            Some(registry_msg) = registry_rx.recv() => {
                // Forward the pre-encoded message to this client's WebSocket,
                // encrypting if Noise session is active
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&registry_msg.data) {
                        Ok(encrypted) => encrypted,
                        Err(_) => continue,
                    }
                } else {
                    registry_msg.data
                };
                let _ = write.send(Message::Binary(send_data)).await;
                continue;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                // If Noise is active, decrypt the incoming message first
                let plaintext_data = if let Some(ref mut ns) = noise_session {
                    match ns.decrypt(&data) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            warn!("[{}] Failed to decrypt incoming message: {}", session, e);
                            continue;
                        }
                    }
                } else {
                    data
                };

                // Check message size (after decryption)
                if plaintext_data.len() > deps.max_message_size {
                    warn!(
                        "[{}] Message too large: {} bytes",
                        session,
                        plaintext_data.len()
                    );
                    continue;
                }

                // Rate limit check
                if !deps.rate_limiter.consume(&routing_id) {
                    warn!("[{}] Rate limited", session);
                    continue;
                }

                // Decode message
                let envelope = match protocol::decode_message(&plaintext_data) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("[{}] Failed to decode message: {}", session, e);
                        continue;
                    }
                };

                // Dispatch to the appropriate handler and process responses
                let result = handle_message(&ctx, &envelope);
                process_handle_result(result, &mut write, &mut noise_session, &ctx).await;
            }
            Ok(Message::Ping(data)) => {
                let _ = write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                debug!("[{}] Client sent close", session);
                break;
            }
            Ok(_) => {
                // Ignore text, pong, etc.
            }
            Err(e) => {
                warn!("[{}] Connection error: {}", session, e);
                break;
            }
        }
    }

    // Unregister from connection registry on disconnect
    deps.registry.unregister(&routing_id, conn_id);
}
