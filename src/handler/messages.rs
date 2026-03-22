// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Message handlers for each protocol message type.

use tracing::{debug, warn};

use super::nonce::{MAX_RECOVERY_PROOF_SIZE, MAX_RECOVERY_QUERY_HASHES, hash_to_hex, hex_to_hash};
use super::types::{HandleResult, HandlerResponse, MessageContext};
use super::verify::{PurgeVerify, RevocationVerify, protocol};
use crate::recovery_storage::StoredRecoveryProof;
use crate::storage::StoredBlob;

/// Handles an `EncryptedUpdate` message: quota check, store, and ack.
pub(super) fn handle_encrypted_update(
    ctx: &MessageContext<'_>,
    update: &protocol::EncryptedUpdate,
    message_id: &str,
) -> HandleResult {
    let deps = ctx.deps;

    // Check per-recipient quota before storing
    if (deps.quota.max_blobs > 0
        && deps.storage.blob_count_for(&update.recipient_id) >= deps.quota.max_blobs)
        || (deps.quota.max_bytes > 0
            && deps
                .storage
                .storage_size_for(&update.recipient_id)
                .saturating_add(update.ciphertext.len())
                > deps.quota.max_bytes)
    {
        debug!("[{}] Quota exceeded for recipient", ctx.session);
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Store blob for recipient
    let blob = StoredBlob::new(update.ciphertext.clone());
    let blob_id = blob.id.clone();
    deps.storage.store(&update.recipient_id, blob);
    deps.metrics.blobs_created.inc();
    deps.metrics
        .blobs_stored
        .set(deps.storage.blob_count() as i64);

    // Track sender for delivery notification (ephemeral, in-memory only)
    deps.blob_sender_map
        .write()
        .insert(blob_id, ctx.routing_id.clone());

    debug!("[{}] Stored blob", ctx.session);
    HandleResult::single(HandlerResponse::SendAck {
        message_id: message_id.to_string(),
        status: protocol::AckStatus::Stored,
    })
}

/// Handles an `Acknowledgment` message: acknowledge blob, optionally forward to sender.
pub(super) fn handle_acknowledgment(
    ctx: &MessageContext<'_>,
    ack: &protocol::Acknowledgment,
) -> HandleResult {
    let deps = ctx.deps;

    if deps.storage.acknowledge(&ctx.routing_id, &ack.message_id) {
        debug!("[{}] Blob acknowledged", ctx.session);

        // If ReceivedByRecipient, forward to the original sender.
        // Suppressed when recipient requested suppress_presence.
        if !ctx.suppress_presence && ack.status == protocol::AckStatus::ReceivedByRecipient {
            let sender_client_id = { deps.blob_sender_map.read().get(&ack.message_id).cloned() };
            if let Some(sender_id) = sender_client_id {
                let fwd_ack =
                    protocol::create_ack(&ack.message_id, protocol::AckStatus::ReceivedByRecipient);
                let mut responses = Vec::new();
                if let Ok(ack_data) = protocol::encode_message(&fwd_ack) {
                    responses.push(HandlerResponse::ForwardToRegistry {
                        target_id: sender_id,
                        data: ack_data,
                    });
                }
                responses.push(HandlerResponse::RemoveFromSenderMap(ack.message_id.clone()));
                return HandleResult { responses };
            }
        }
    }

    HandleResult::empty()
}

/// Handles a `RecoveryProofStore` message: validate hash, store, ack.
pub(super) fn handle_recovery_proof_store(
    ctx: &MessageContext<'_>,
    store_msg: &protocol::RecoveryProofStore,
    message_id: &str,
) -> HandleResult {
    // R-H3: Reject oversized proof data to prevent storage exhaustion
    if store_msg.proof_data.len() > MAX_RECOVERY_PROOF_SIZE {
        warn!(
            "[{}] Recovery proof rejected: {} bytes exceeds limit of {}",
            ctx.session,
            store_msg.proof_data.len(),
            MAX_RECOVERY_PROOF_SIZE
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    if let Ok(key_hash) = hex_to_hash(&store_msg.key_hash) {
        let proof = StoredRecoveryProof::new(key_hash, store_msg.proof_data.clone());
        ctx.deps.recovery_storage.store(proof);
        ctx.deps.metrics.recovery_vouchers_total.inc();
        ctx.deps.metrics.recovery_proofs_active.inc();

        debug!("[{}] Stored recovery proof", ctx.session);
        HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Stored,
        })
    } else {
        warn!("[{}] Invalid key hash format", ctx.session);
        HandleResult::empty()
    }
}

/// Handles a `RecoveryProofQuery` message: batch query, return results.
pub(super) fn handle_recovery_proof_query(
    ctx: &MessageContext<'_>,
    query: &protocol::RecoveryProofQuery,
) -> HandleResult {
    // R-H2: Reject queries with too many hashes to prevent DB mutex exhaustion
    if query.key_hashes.len() > MAX_RECOVERY_QUERY_HASHES {
        warn!(
            "[{}] Recovery query rejected: {} hashes exceeds limit of {}",
            ctx.session,
            query.key_hashes.len(),
            MAX_RECOVERY_QUERY_HASHES
        );
        return HandleResult::single(HandlerResponse::Skip);
    }

    let key_hashes: Vec<[u8; 32]> = query
        .key_hashes
        .iter()
        .filter_map(|h| hex_to_hash(h).ok())
        .collect();

    let results = ctx.deps.recovery_storage.batch_get(&key_hashes);

    let entries: Vec<protocol::RecoveryProofEntry> = results
        .into_iter()
        .map(|(hash, proof)| protocol::RecoveryProofEntry {
            key_hash: hash_to_hex(&hash),
            proof_data: proof.proof_data,
        })
        .collect();

    debug!(
        "Processed recovery query with {} hashes",
        query.key_hashes.len()
    );

    let response = protocol::create_recovery_response(entries);
    HandleResult::single(HandlerResponse::SendEnvelope(response))
}

/// Handles a `PurgeRequest`: verify signature, delete data, respond.
pub(super) fn handle_purge_request(
    ctx: &MessageContext<'_>,
    purge: &protocol::PurgeRequest,
    message_id: &str,
) -> HandleResult {
    let deps = ctx.deps;

    // Require authenticated purge requests (v2 signature)
    if purge.is_authenticated() {
        if let Err(e) = purge.verify_signature() {
            warn!(
                "[{}] Rejecting purge with invalid signature: {}",
                ctx.session, e
            );
            return HandleResult::single(HandlerResponse::SendAck {
                message_id: message_id.to_string(),
                status: protocol::AckStatus::Failed,
            });
        }
    } else {
        warn!(
            "[{}] Rejecting unsigned purge request (v2 signature required)",
            ctx.session
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Delete all stored blobs for this client's routing ID
    let blobs_deleted = deps.storage.delete_all_for(&ctx.routing_id);

    // Optionally delete recovery proofs
    let recovery_proofs_deleted = if purge.include_recovery_proofs {
        if let Some(ref key_hash_hex) = purge.recovery_key_hash {
            if let Ok(decoded) = hex::decode(key_hash_hex) {
                if decoded.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&decoded);
                    if deps.recovery_storage.remove(&hash) {
                        deps.metrics.recovery_proofs_active.dec();
                        1
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    // Delete forwarding hints for this routing_id (federation cleanup)
    if let Some(ref hint_store) = deps.hint_store {
        let hints_deleted = hint_store.delete_all_for(&ctx.routing_id);
        if hints_deleted > 0 {
            debug!(
                "[{}] Purged {} forwarding hints",
                ctx.session, hints_deleted
            );
        }
    }

    debug!(
        "[{}] Purged {} blobs, {} recovery proofs",
        ctx.session, blobs_deleted, recovery_proofs_deleted
    );

    // Send purge response
    let response =
        protocol::create_purge_response(message_id, blobs_deleted, recovery_proofs_deleted);
    HandleResult::single(HandlerResponse::SendEnvelope(response))
}

/// Handles an `AccountRevoked` message: verify signature, validate, store as blob, ack.
///
/// F-01 fix: Requires valid Ed25519 signature over canonical revocation bytes.
/// Without verification, any client could send a revocation for any recipient.
pub(super) fn handle_account_revoked(
    ctx: &MessageContext<'_>,
    revoked: &protocol::AccountRevoked,
    envelope: &protocol::MessageEnvelope,
) -> HandleResult {
    let deps = ctx.deps;

    // F-01: Verify Ed25519 signature over canonical revocation bytes.
    // Rejects unsigned, tampered, expired, or forged revocations.
    if let Err(e) = revoked.verify_revocation() {
        warn!(
            "[{}] Rejecting AccountRevoked with invalid signature: {}",
            ctx.session, e
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Validate recipient_id format (hex-encoded, 64 chars).
    // verify_revocation already checks hex decode + 32 bytes for recipient_id,
    // but this guards the storage key format explicitly.
    if revoked.recipient_id.len() != 64
        || !revoked.recipient_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        debug!("[{}] AccountRevoked: invalid recipient_id", ctx.session);
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Check per-recipient quota
    if deps.quota.max_blobs > 0
        && deps.storage.blob_count_for(&revoked.recipient_id) >= deps.quota.max_blobs
    {
        debug!(
            "[{}] AccountRevoked: quota exceeded for recipient",
            ctx.session
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Re-encode the entire envelope as a blob for the recipient
    match protocol::encode_message(envelope) {
        Ok(blob_data) => {
            let blob = StoredBlob::new(blob_data);
            deps.storage.store(&revoked.recipient_id, blob);

            debug!("[{}] Stored AccountRevoked for recipient", ctx.session);
            HandleResult::single(HandlerResponse::SendAck {
                message_id: envelope.message_id.clone(),
                status: protocol::AckStatus::Stored,
            })
        }
        Err(e) => {
            warn!(
                "[{}] AccountRevoked: failed to re-encode envelope: {}",
                ctx.session, e
            );
            HandleResult::single(HandlerResponse::SendAck {
                message_id: envelope.message_id.clone(),
                status: protocol::AckStatus::Failed,
            })
        }
    }
}

/// Handles a single decoded message by dispatching to the appropriate handler.
///
/// Returns a `HandleResult` describing the actions the message loop should take.
pub(super) fn handle_message(
    ctx: &MessageContext<'_>,
    envelope: &protocol::MessageEnvelope,
) -> HandleResult {
    match &envelope.payload {
        protocol::MessagePayload::EncryptedUpdate(update) => {
            handle_encrypted_update(ctx, update, &envelope.message_id)
        }
        protocol::MessagePayload::Acknowledgment(ack) => handle_acknowledgment(ctx, ack),
        protocol::MessagePayload::Handshake(_) => {
            // Ignore duplicate handshakes
            HandleResult::empty()
        }
        protocol::MessagePayload::RecoveryProofStore(store_msg) => {
            // Recovery operations have a stricter rate limit (anti-enumeration)
            if !ctx.deps.recovery_rate_limiter.consume(&ctx.routing_id) {
                warn!("[{}] Recovery rate limited", ctx.session);
                return HandleResult::single(HandlerResponse::Skip);
            }
            handle_recovery_proof_store(ctx, store_msg, &envelope.message_id)
        }
        protocol::MessagePayload::RecoveryProofQuery(query) => {
            // Recovery operations have a stricter rate limit (anti-enumeration)
            if !ctx.deps.recovery_rate_limiter.consume(&ctx.routing_id) {
                warn!("[{}] Recovery rate limited", ctx.session);
                return HandleResult::single(HandlerResponse::Skip);
            }
            handle_recovery_proof_query(ctx, query)
        }
        protocol::MessagePayload::RecoveryProofResponse(_) => {
            debug!("[{}] Unexpected RecoveryProofResponse", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::HandshakeAck(_) => {
            debug!("[{}] Unexpected HandshakeAck", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::PurgeRequest(purge) => {
            handle_purge_request(ctx, purge, &envelope.message_id)
        }
        protocol::MessagePayload::AccountRevoked(revoked) => {
            handle_account_revoked(ctx, revoked, envelope)
        }
        protocol::MessagePayload::PurgeResponse(_) => {
            debug!("[{}] Unexpected PurgeResponse", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::ForwardingHints(_) => {
            debug!("[{}] Unexpected ForwardingHints", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::DeviceLinkRelay(_) => {
            debug!("[{}] Unexpected DeviceLinkRelay", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::Unknown => {
            debug!("[{}] Unknown message type", ctx.session);
            HandleResult::empty()
        }
    }
}
