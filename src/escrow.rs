// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Escrow Store
//!
//! In-memory store for relay-mediated card exchange via gated blobs.
//! Each gate has exactly 2 slots (initiator + responder). A blob
//! can only be retrieved once both slots are filled.
//!
//! All blobs are opaque encrypted ciphertext — the relay never sees
//! plaintext (ADR-002, ADR-004). Expired gates are swept periodically.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use vauchi_protocol::escrow::{
    EscrowMessage, EscrowResponse, MAX_BLOB_BYTES, MAX_SLOTS_PER_GATE, MAX_TTL_SECONDS,
};

/// Maximum number of active gates before rejecting new deposits.
pub const MAX_ACTIVE_GATES: usize = 10_000;

/// A single slot within an escrow gate.
struct EscrowSlot {
    slot_hash: [u8; 32],
    blob: String,
}

/// A gate holding up to MAX_SLOTS_PER_GATE slots.
struct EscrowGate {
    slots: Vec<EscrowSlot>,
    expires_at: Instant,
}

/// In-memory escrow store for gated blob exchange.
pub struct EscrowStore {
    gates: RwLock<HashMap<[u8; 32], EscrowGate>>,
    max_gates: usize,
}

impl EscrowStore {
    /// Create a new escrow store with the given gate capacity.
    pub fn new(max_gates: usize) -> Self {
        Self {
            gates: RwLock::new(HashMap::new()),
            max_gates,
        }
    }

    // TODO(PFC): Escrow methods embed Instant::now() — see 2026-07-06-relay-pfc-violations R17
    /// Handle an escrow message and return the appropriate response.
    pub fn handle(&self, msg: EscrowMessage) -> EscrowResponse {
        match msg {
            EscrowMessage::Put {
                gate_hash,
                slot_hash,
                blob,
                ttl_seconds,
            } => self.put(&gate_hash, &slot_hash, blob, ttl_seconds),
            EscrowMessage::Get {
                gate_hash,
                slot_hash,
            } => self.get(&gate_hash, &slot_hash),
            EscrowMessage::Count { gate_hash } => self.count(&gate_hash),
        }
    }

    fn put(
        &self,
        gate_hash_hex: &str,
        slot_hash_hex: &str,
        blob: String,
        ttl_seconds: u32,
    ) -> EscrowResponse {
        // Validate blob size (base64 decoded upper bound).
        let decoded_upper_bound = blob.len() * 3 / 4;
        if decoded_upper_bound > MAX_BLOB_BYTES {
            return EscrowResponse::BlobTooLarge;
        }

        if ttl_seconds > MAX_TTL_SECONDS {
            // TTL too long — reject. Use BlobTooLarge as closest fit,
            // but the client should have validated this.
            return EscrowResponse::BlobTooLarge;
        }

        let gate_hash = match hex_to_hash(gate_hash_hex) {
            Some(h) => h,
            None => return EscrowResponse::NotFound,
        };
        let slot_hash = match hex_to_hash(slot_hash_hex) {
            Some(h) => h,
            None => return EscrowResponse::NotFound,
        };

        let mut gates = self.gates.write();
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(u64::from(ttl_seconds));

        if let Some(gate) = gates.get_mut(&gate_hash) {
            // Check if expired.
            if now > gate.expires_at {
                gates.remove(&gate_hash);
                // Fall through to create new gate below.
            } else {
                // Check for duplicate slot.
                if gate.slots.iter().any(|s| s.slot_hash == slot_hash) {
                    return EscrowResponse::AlreadyExists;
                }
                // Check gate capacity.
                if gate.slots.len() >= MAX_SLOTS_PER_GATE as usize {
                    return EscrowResponse::GateFull;
                }
                gate.slots.push(EscrowSlot { slot_hash, blob });
                return EscrowResponse::Stored;
            }
        }

        // Create new gate.
        if gates.len() >= self.max_gates {
            return EscrowResponse::GateFull;
        }

        gates.insert(
            gate_hash,
            EscrowGate {
                slots: vec![EscrowSlot { slot_hash, blob }],
                expires_at,
            },
        );
        EscrowResponse::Stored
    }

    fn get(&self, gate_hash_hex: &str, slot_hash_hex: &str) -> EscrowResponse {
        let gate_hash = match hex_to_hash(gate_hash_hex) {
            Some(h) => h,
            None => return EscrowResponse::NotFound,
        };
        let slot_hash = match hex_to_hash(slot_hash_hex) {
            Some(h) => h,
            None => return EscrowResponse::NotFound,
        };

        let gates = self.gates.read();
        let gate = match gates.get(&gate_hash) {
            Some(g) if Instant::now() <= g.expires_at => g,
            _ => return EscrowResponse::NotFound,
        };

        // Gate must have both slots filled before retrieval.
        if gate.slots.len() < MAX_SLOTS_PER_GATE as usize {
            return EscrowResponse::NotReady {
                count: gate.slots.len() as u8,
            };
        }

        // Verify the requester's slot exists (authentication).
        // Without this, anyone with the gate_hash could retrieve blobs.
        if !gate.slots.iter().any(|s| s.slot_hash == slot_hash) {
            return EscrowResponse::NotFound;
        }

        // Return the OTHER slot's blob (not the requester's own).
        match gate.slots.iter().find(|s| s.slot_hash != slot_hash) {
            Some(other) => EscrowResponse::Blob {
                blob: other.blob.clone(),
            },
            None => EscrowResponse::NotFound,
        }
    }

    fn count(&self, gate_hash_hex: &str) -> EscrowResponse {
        let gate_hash = match hex_to_hash(gate_hash_hex) {
            Some(h) => h,
            None => return EscrowResponse::NotFound,
        };

        let gates = self.gates.read();
        match gates.get(&gate_hash) {
            Some(gate) if Instant::now() <= gate.expires_at => EscrowResponse::Count {
                count: gate.slots.len() as u8,
            },
            _ => EscrowResponse::NotFound,
        }
    }

    /// Remove expired gates. Call periodically.
    ///
    /// Returns the number of gates removed.
    pub fn cleanup_expired(&self) -> usize {
        let mut gates = self.gates.write();
        let before = gates.len();
        let now = Instant::now();
        gates.retain(|_, gate| now <= gate.expires_at);
        before - gates.len()
    }

    /// Current number of active gates.
    pub fn gate_count(&self) -> usize {
        self.gates.read().len()
    }
}

fn hex_to_hash(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(arr)
}
