// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Connection Registry
//!
//! Tracks connected clients so the relay can send delivery notifications
//! (e.g., "Delivered" acks) to senders when recipients pick up blobs.
//!
//! The registry maps client routing IDs to message channels. When a blob
//! is delivered to a recipient, the relay looks up the original sender
//! and forwards a Delivered acknowledgment if the sender is online.
//!
//! Supports multiple devices per identity: when two devices connect with
//! the same routing ID, both receive forwarded messages (fan-out).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use tokio::sync::mpsc;

/// Unique identifier for a registered connection.
/// Used to unregister a specific device without removing other devices
/// sharing the same routing ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(u64);

/// A message that can be sent to a connected client via the registry.
#[derive(Debug, Clone)]
pub struct RegistryMessage {
    /// The encoded binary frame to send over WebSocket.
    pub data: Vec<u8>,
}

/// A single connection entry: unique ID + channel sender.
struct ConnectionEntry {
    id: ConnectionId,
    sender: mpsc::Sender<RegistryMessage>,
}

/// Thread-safe registry of connected clients.
///
/// Each client is identified by their routing ID (client_id from handshake)
/// and associated with one or more async channel senders for delivering
/// messages. Multiple devices of the same identity can be registered
/// simultaneously — messages are fanned out to all connections.
pub struct ConnectionRegistry {
    connections: RwLock<HashMap<String, Vec<ConnectionEntry>>>,
    next_id: AtomicU64,
}

impl ConnectionRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        ConnectionRegistry {
            connections: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Registers a connected client. Returns the connection ID (for
    /// unregistration) and the receiving end of the channel.
    ///
    /// Multiple devices of the same identity can register concurrently.
    /// Each gets its own channel and connection ID.
    pub fn register(&self, client_id: &str) -> (ConnectionId, mpsc::Receiver<RegistryMessage>) {
        let conn_id = ConnectionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = mpsc::channel(64);
        let entry = ConnectionEntry {
            id: conn_id,
            sender: tx,
        };
        let mut connections = self.connections.write().unwrap();
        connections
            .entry(client_id.to_string())
            .or_default()
            .push(entry);
        (conn_id, rx)
    }

    /// Unregisters a specific connection by its connection ID.
    /// Other connections for the same routing ID remain active.
    pub fn unregister(&self, client_id: &str, conn_id: ConnectionId) {
        let mut connections = self.connections.write().unwrap();
        if let Some(entries) = connections.get_mut(client_id) {
            entries.retain(|e| e.id != conn_id);
            if entries.is_empty() {
                connections.remove(client_id);
            }
        }
    }

    /// Sends a message to all connections for a client. Returns true if
    /// at least one connection received the message.
    ///
    /// Dead connections (closed channels) are cleaned up automatically.
    pub fn try_send(&self, client_id: &str, msg: RegistryMessage) -> bool {
        let mut connections = self.connections.write().unwrap();
        if let Some(entries) = connections.get_mut(client_id) {
            let mut any_sent = false;
            entries.retain(|entry| {
                match entry.sender.try_send(msg.clone()) {
                    Ok(()) => {
                        any_sent = true;
                        true // keep alive
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false, // remove dead
                    Err(mpsc::error::TrySendError::Full(_)) => true,    // keep, channel full
                }
            });
            if entries.is_empty() {
                connections.remove(client_id);
            }
            any_sent
        } else {
            false
        }
    }

    /// Returns the number of unique client IDs with active connections.
    #[allow(dead_code)]
    pub fn connected_count(&self) -> usize {
        let connections = self.connections.read().unwrap();
        connections.len()
    }

    /// Returns the total number of active connections across all clients.
    #[allow(dead_code)]
    pub fn total_connections(&self) -> usize {
        let connections = self.connections.read().unwrap();
        connections.values().map(|v| v.len()).sum()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// INLINE_TEST_REQUIRED: Unit tests for ConnectionRegistry internals (Vec<ConnectionEntry> fan-out, dead channel cleanup)
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_send() {
        let registry = ConnectionRegistry::new();
        let (_id, mut rx) = registry.register("client-1");

        let msg = RegistryMessage {
            data: vec![1, 2, 3],
        };
        assert!(registry.try_send("client-1", msg));

        let received = rx.recv().await.unwrap();
        assert_eq!(received.data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_send_to_offline_client() {
        let registry = ConnectionRegistry::new();

        let msg = RegistryMessage {
            data: vec![1, 2, 3],
        };
        assert!(!registry.try_send("nonexistent", msg));
    }

    #[tokio::test]
    async fn test_unregister() {
        let registry = ConnectionRegistry::new();
        let (id, _rx) = registry.register("client-1");

        assert_eq!(registry.connected_count(), 1);
        registry.unregister("client-1", id);
        assert_eq!(registry.connected_count(), 0);

        let msg = RegistryMessage {
            data: vec![1, 2, 3],
        };
        assert!(!registry.try_send("client-1", msg));
    }

    #[tokio::test]
    async fn test_multi_device_fan_out() {
        let registry = ConnectionRegistry::new();
        let (_id1, mut rx1) = registry.register("client-1");
        let (_id2, mut rx2) = registry.register("client-1");

        // Both connections should be registered
        assert_eq!(registry.connected_count(), 1);
        assert_eq!(registry.total_connections(), 2);

        let msg = RegistryMessage {
            data: vec![4, 5, 6],
        };
        assert!(registry.try_send("client-1", msg));

        // Both receivers should get the message
        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.data, vec![4, 5, 6]);
        assert_eq!(r2.data, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_unregister_specific_device() {
        let registry = ConnectionRegistry::new();
        let (id1, _rx1) = registry.register("client-1");
        let (_id2, mut rx2) = registry.register("client-1");

        assert_eq!(registry.total_connections(), 2);

        // Unregister only device-1
        registry.unregister("client-1", id1);
        assert_eq!(registry.total_connections(), 1);
        assert_eq!(registry.connected_count(), 1);

        // Device-2 should still receive messages
        let msg = RegistryMessage {
            data: vec![7, 8, 9],
        };
        assert!(registry.try_send("client-1", msg));
        let received = rx2.recv().await.unwrap();
        assert_eq!(received.data, vec![7, 8, 9]);
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let registry = ConnectionRegistry::new();
        let (_id1, mut rx1) = registry.register("client-1");
        let (_id2, mut rx2) = registry.register("client-2");

        assert_eq!(registry.connected_count(), 2);

        registry.try_send("client-1", RegistryMessage { data: vec![1] });
        registry.try_send("client-2", RegistryMessage { data: vec![2] });

        assert_eq!(rx1.recv().await.unwrap().data, vec![1]);
        assert_eq!(rx2.recv().await.unwrap().data, vec![2]);
    }

    #[tokio::test]
    async fn test_dead_channel_cleanup() {
        let registry = ConnectionRegistry::new();
        let (_id1, rx1) = registry.register("client-1");
        let (_id2, mut rx2) = registry.register("client-1");

        // Drop rx1 — its channel is now closed
        drop(rx1);

        // try_send should clean up the dead channel and still deliver to rx2
        let msg = RegistryMessage { data: vec![10, 11] };
        assert!(registry.try_send("client-1", msg));
        assert_eq!(registry.total_connections(), 1);

        let received = rx2.recv().await.unwrap();
        assert_eq!(received.data, vec![10, 11]);
    }
}
