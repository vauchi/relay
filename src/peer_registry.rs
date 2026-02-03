// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Peer Registry
//!
//! Tracks connected federation peers, their capacity, and connection status.
//! Each peer entry holds an optional sender channel for sending federation
//! messages to that peer.

use std::collections::HashMap;
use std::sync::RwLock;

use tokio::sync::mpsc;

/// Connection status of a federation peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    Connected,
    Draining,
    Disconnected,
}

/// Information about a connected federation peer.
#[derive(Debug)]
pub struct PeerInfo {
    pub relay_id: String,
    pub url: String,
    pub capacity_used_bytes: usize,
    pub capacity_max_bytes: usize,
    pub status: PeerStatus,
    /// Channel for sending encoded federation messages to this peer.
    pub sender: Option<mpsc::Sender<Vec<u8>>>,
}

impl Clone for PeerInfo {
    fn clone(&self) -> Self {
        PeerInfo {
            relay_id: self.relay_id.clone(),
            url: self.url.clone(),
            capacity_used_bytes: self.capacity_used_bytes,
            capacity_max_bytes: self.capacity_max_bytes,
            status: self.status.clone(),
            sender: self.sender.clone(),
        }
    }
}

/// Registry of connected federation peers.
pub struct PeerRegistry {
    peers: RwLock<HashMap<String, PeerInfo>>,
    /// Refuse threshold ratio (e.g. 0.95). Peers above this are considered at capacity.
    refuse_threshold: f64,
}

impl PeerRegistry {
    pub fn new(refuse_threshold: f64) -> Self {
        PeerRegistry {
            peers: RwLock::new(HashMap::new()),
            refuse_threshold,
        }
    }

    /// Registers or updates a peer.
    pub fn register_peer(&self, info: PeerInfo) {
        let mut peers = self.peers.write().unwrap();
        peers.insert(info.relay_id.clone(), info);
    }

    /// Unregisters a peer by relay_id.
    pub fn unregister_peer(&self, relay_id: &str) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(relay_id);
    }

    /// Updates capacity metrics for a peer.
    pub fn update_capacity(&self, relay_id: &str, used: usize, max: usize) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(relay_id) {
            peer.capacity_used_bytes = used;
            peer.capacity_max_bytes = max;
        }
    }

    /// Sets the sender channel for a peer.
    pub fn set_sender(&self, relay_id: &str, sender: mpsc::Sender<Vec<u8>>) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(relay_id) {
            peer.sender = Some(sender);
        }
    }

    /// Sets the status for a peer.
    pub fn set_status(&self, relay_id: &str, status: PeerStatus) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(relay_id) {
            peer.status = status;
        }
    }

    /// Finds a connected peer with available capacity (below refuse threshold).
    pub fn get_peer_with_capacity(&self) -> Option<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers.values().find(|p| {
            p.status == PeerStatus::Connected
                && p.sender.is_some()
                && p.capacity_max_bytes > 0
                && (p.capacity_used_bytes as f64 / p.capacity_max_bytes as f64)
                    < self.refuse_threshold
        }).cloned()
    }

    /// Returns the number of registered peers.
    pub fn peer_count(&self) -> usize {
        let peers = self.peers.read().unwrap();
        peers.len()
    }

    /// Returns all connected peers.
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(relay_id: &str, used: usize, max: usize) -> PeerInfo {
        PeerInfo {
            relay_id: relay_id.to_string(),
            url: format!("ws://{}:8080", relay_id),
            capacity_used_bytes: used,
            capacity_max_bytes: max,
            status: PeerStatus::Connected,
            sender: None,
        }
    }

    #[test]
    fn test_register_and_count() {
        let registry = PeerRegistry::new(0.95);
        assert_eq!(registry.peer_count(), 0);

        registry.register_peer(make_peer("peer-a", 100, 1000));
        assert_eq!(registry.peer_count(), 1);

        registry.register_peer(make_peer("peer-b", 200, 1000));
        assert_eq!(registry.peer_count(), 2);
    }

    #[test]
    fn test_unregister() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        registry.unregister_peer("peer-a");
        assert_eq!(registry.peer_count(), 0);
    }

    #[test]
    fn test_update_capacity() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        registry.update_capacity("peer-a", 900, 1000);

        let peers = registry.connected_peers();
        assert_eq!(peers[0].capacity_used_bytes, 900);
    }

    #[test]
    fn test_get_peer_with_capacity_none_without_sender() {
        let registry = PeerRegistry::new(0.95);
        // Peer without sender channel
        registry.register_peer(make_peer("peer-a", 100, 1000));
        assert!(registry.get_peer_with_capacity().is_none());
    }

    #[tokio::test]
    async fn test_get_peer_with_capacity_with_sender() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        let (tx, _rx) = mpsc::channel(16);
        registry.set_sender("peer-a", tx);

        let peer = registry.get_peer_with_capacity();
        assert!(peer.is_some());
        assert_eq!(peer.unwrap().relay_id, "peer-a");
    }

    #[tokio::test]
    async fn test_get_peer_with_capacity_none_when_full() {
        let registry = PeerRegistry::new(0.95);
        // Peer at 96% (above 95% threshold)
        registry.register_peer(make_peer("peer-a", 960, 1000));
        let (tx, _rx) = mpsc::channel(16);
        registry.set_sender("peer-a", tx);

        assert!(registry.get_peer_with_capacity().is_none());
    }

    #[test]
    fn test_set_status_draining() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        registry.set_status("peer-a", PeerStatus::Draining);

        let peers = registry.connected_peers();
        assert!(peers.is_empty()); // Draining peers not returned as connected
    }

    #[test]
    fn test_connected_peers() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        registry.register_peer(make_peer("peer-b", 200, 1000));
        registry.set_status("peer-b", PeerStatus::Disconnected);

        let connected = registry.connected_peers();
        assert_eq!(connected.len(), 1);
        assert_eq!(connected[0].relay_id, "peer-a");
    }
}
