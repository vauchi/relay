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

use std::collections::HashMap;
use std::sync::RwLock;

use tokio::sync::mpsc;

/// A message that can be sent to a connected client via the registry.
#[derive(Debug, Clone)]
pub struct RegistryMessage {
    /// The encoded binary frame to send over WebSocket.
    pub data: Vec<u8>,
}

/// Thread-safe registry of connected clients.
///
/// Each client is identified by their routing ID (client_id from handshake)
/// and associated with an async channel sender for delivering messages.
pub struct ConnectionRegistry {
    connections: RwLock<HashMap<String, mpsc::Sender<RegistryMessage>>>,
}

impl ConnectionRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        ConnectionRegistry {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a connected client. Returns the receiving end of the channel.
    ///
    /// If the client was already registered (reconnection), the old channel is
    /// replaced and the old receiver will see the channel close.
    pub fn register(&self, client_id: &str) -> mpsc::Receiver<RegistryMessage> {
        let (tx, rx) = mpsc::channel(64);
        let mut connections = self.connections.write().unwrap();
        connections.insert(client_id.to_string(), tx);
        rx
    }

    /// Unregisters a client when they disconnect.
    pub fn unregister(&self, client_id: &str) {
        let mut connections = self.connections.write().unwrap();
        connections.remove(client_id);
    }

    /// Sends a message to a connected client. Returns true if the client is
    /// online and the message was queued, false if the client is offline.
    pub fn try_send(&self, client_id: &str, msg: RegistryMessage) -> bool {
        let connections = self.connections.read().unwrap();
        if let Some(tx) = connections.get(client_id) {
            tx.try_send(msg).is_ok()
        } else {
            false
        }
    }

    /// Returns the number of currently connected clients.
    #[allow(dead_code)]
    pub fn connected_count(&self) -> usize {
        let connections = self.connections.read().unwrap();
        connections.len()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_send() {
        let registry = ConnectionRegistry::new();
        let mut rx = registry.register("client-1");

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
        let _rx = registry.register("client-1");

        assert_eq!(registry.connected_count(), 1);
        registry.unregister("client-1");
        assert_eq!(registry.connected_count(), 0);

        let msg = RegistryMessage {
            data: vec![1, 2, 3],
        };
        assert!(!registry.try_send("client-1", msg));
    }

    #[tokio::test]
    async fn test_reconnection_replaces_channel() {
        let registry = ConnectionRegistry::new();
        let mut _rx_old = registry.register("client-1");
        let mut rx_new = registry.register("client-1");

        // Old channel should be replaced
        assert_eq!(registry.connected_count(), 1);

        let msg = RegistryMessage {
            data: vec![4, 5, 6],
        };
        assert!(registry.try_send("client-1", msg));

        // New receiver should get the message
        let received = rx_new.recv().await.unwrap();
        assert_eq!(received.data, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let registry = ConnectionRegistry::new();
        let mut rx1 = registry.register("client-1");
        let mut rx2 = registry.register("client-2");

        assert_eq!(registry.connected_count(), 2);

        registry.try_send("client-1", RegistryMessage { data: vec![1] });
        registry.try_send("client-2", RegistryMessage { data: vec![2] });

        assert_eq!(rx1.recv().await.unwrap().data, vec![1]);
        assert_eq!(rx2.recv().await.unwrap().data, vec![2]);
    }
}
