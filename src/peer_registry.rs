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

/// How the peer was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerOrigin {
    /// Statically configured in the relay config (always retry).
    Configured,
    /// Dynamically discovered via gossip (TTL-based).
    Discovered,
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
    /// How this peer was discovered.
    pub origin: PeerOrigin,
    /// Unix timestamp when this peer was last seen (for TTL expiry of discovered peers).
    pub last_seen_secs: u64,
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
            origin: self.origin.clone(),
            last_seen_secs: self.last_seen_secs,
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
        peers
            .values()
            .find(|p| {
                p.status == PeerStatus::Connected
                    && p.sender.is_some()
                    && p.capacity_max_bytes > 0
                    && (p.capacity_used_bytes as f64 / p.capacity_max_bytes as f64)
                        < self.refuse_threshold
            })
            .cloned()
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

    /// Returns all known peers (both configured and discovered).
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers.values().cloned().collect()
    }

    /// Adds or updates a dynamically discovered peer from gossip.
    ///
    /// If the peer already exists and is configured, updates last_seen
    /// but does not change origin. If the peer is new, adds it as
    /// `Discovered` with `Disconnected` status.
    ///
    /// Returns `true` if a new peer was added.
    pub fn add_discovered_peer(
        &self,
        relay_id: &str,
        url: &str,
        capacity_pct: u8,
        last_seen_secs: u64,
    ) -> bool {
        let mut peers = self.peers.write().unwrap();

        if let Some(existing) = peers.get_mut(relay_id) {
            // Update last_seen if the incoming timestamp is fresher
            if last_seen_secs > existing.last_seen_secs {
                existing.last_seen_secs = last_seen_secs;
                // Update capacity estimate
                if existing.capacity_max_bytes > 0 {
                    existing.capacity_used_bytes =
                        (existing.capacity_max_bytes as u64 * capacity_pct as u64 / 100) as usize;
                }
            }
            false
        } else {
            peers.insert(
                relay_id.to_string(),
                PeerInfo {
                    relay_id: relay_id.to_string(),
                    url: url.to_string(),
                    capacity_used_bytes: 0,
                    capacity_max_bytes: 0,
                    status: PeerStatus::Disconnected,
                    sender: None,
                    origin: PeerOrigin::Discovered,
                    last_seen_secs,
                },
            );
            true
        }
    }

    /// Removes dynamically discovered peers that haven't been seen within `max_age_secs`.
    ///
    /// Only removes `Discovered` peers; `Configured` peers are never removed.
    /// Returns the number of peers removed.
    pub fn remove_stale_peers(&self, now_secs: u64, max_age_secs: u64) -> usize {
        let mut peers = self.peers.write().unwrap();
        let before = peers.len();

        peers.retain(|_, peer| {
            if peer.origin == PeerOrigin::Configured {
                return true; // never remove configured peers
            }
            // Keep if last_seen is within the TTL
            now_secs.saturating_sub(peer.last_seen_secs) < max_age_secs
        });

        before - peers.len()
    }

    /// Updates the last_seen timestamp for a peer.
    pub fn touch_peer(&self, relay_id: &str, now_secs: u64) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get_mut(relay_id) {
            peer.last_seen_secs = now_secs;
        }
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
            origin: PeerOrigin::Configured,
            last_seen_secs: 1000,
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

    #[test]
    fn test_add_discovered_peer_new() {
        let registry = PeerRegistry::new(0.95);
        let added = registry.add_discovered_peer("peer-d", "ws://peer-d:8080", 50, 2000);
        assert!(added);
        assert_eq!(registry.peer_count(), 1);

        let peers = registry.all_peers();
        assert_eq!(peers[0].origin, PeerOrigin::Discovered);
        assert_eq!(peers[0].status, PeerStatus::Disconnected);
        assert_eq!(peers[0].last_seen_secs, 2000);
    }

    #[test]
    fn test_add_discovered_peer_existing_configured() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));

        // Try adding same peer via gossip — should not add
        let added = registry.add_discovered_peer("peer-a", "ws://peer-a:8080", 50, 3000);
        assert!(!added);
        assert_eq!(registry.peer_count(), 1);

        // But last_seen should be updated
        let peers = registry.all_peers();
        assert_eq!(peers[0].last_seen_secs, 3000);
        // Origin should remain Configured
        assert_eq!(peers[0].origin, PeerOrigin::Configured);
    }

    #[test]
    fn test_add_discovered_peer_stale_timestamp() {
        let registry = PeerRegistry::new(0.95);
        registry.add_discovered_peer("peer-d", "ws://peer-d:8080", 50, 2000);

        // Older timestamp should not update last_seen
        registry.add_discovered_peer("peer-d", "ws://peer-d:8080", 60, 1500);

        let peers = registry.all_peers();
        assert_eq!(peers[0].last_seen_secs, 2000); // unchanged
    }

    #[test]
    fn test_remove_stale_discovered_peers() {
        let registry = PeerRegistry::new(0.95);
        // Configured peer — should never be removed
        registry.register_peer(make_peer("configured", 100, 1000));
        // Discovered peer — last seen at t=1000
        registry.add_discovered_peer("discovered-old", "ws://old:8080", 50, 1000);
        // Discovered peer — last seen at t=3500
        registry.add_discovered_peer("discovered-new", "ws://new:8080", 50, 3500);

        assert_eq!(registry.peer_count(), 3);

        // At now=5000, TTL=3600:
        // discovered-old: age=4000 >= 3600 → removed
        // discovered-new: age=1500 < 3600 → kept
        // configured: always kept
        let removed = registry.remove_stale_peers(5000, 3600);
        assert_eq!(removed, 1);
        assert_eq!(registry.peer_count(), 2);
    }

    #[test]
    fn test_remove_stale_never_removes_configured() {
        let registry = PeerRegistry::new(0.95);
        let mut peer = make_peer("configured", 100, 1000);
        peer.last_seen_secs = 0; // very old
        registry.register_peer(peer);

        let removed = registry.remove_stale_peers(100000, 3600);
        assert_eq!(removed, 0);
        assert_eq!(registry.peer_count(), 1);
    }

    #[test]
    fn test_touch_peer() {
        let registry = PeerRegistry::new(0.95);
        registry.add_discovered_peer("peer-d", "ws://peer-d:8080", 50, 1000);

        registry.touch_peer("peer-d", 5000);

        let peers = registry.all_peers();
        assert_eq!(peers[0].last_seen_secs, 5000);
    }

    #[test]
    fn test_all_peers() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_peer("peer-a", 100, 1000));
        registry.add_discovered_peer("peer-d", "ws://peer-d:8080", 50, 2000);
        registry.set_status("peer-a", PeerStatus::Disconnected);

        let all = registry.all_peers();
        assert_eq!(all.len(), 2);
    }
}

/// Gossip-based peer discovery.
///
/// Periodic gossip task that advertises known peers to all connected
/// federation peers. On receiving a peer advertisement, new peers are
/// merged into the peer registry with a TTL. Stale peers are cleaned
/// up periodically.
pub mod gossip {
    use std::sync::Arc;
    use std::time::Duration;

    use tracing::{debug, info, warn};

    use super::PeerRegistry;
    use crate::config::RelayConfig;
    use crate::federation_protocol::{
        create_federation_envelope, encode_federation_message, AdvertisedPeer, FederationPayload,
    };

    /// Runs the periodic gossip advertisement task.
    ///
    /// On each tick:
    /// 1. Builds a list of all known peers (excluding self)
    /// 2. Sends a `PeerAdvertisement` to all connected peers
    /// 3. Removes stale discovered peers
    pub async fn run_gossip_task(
        own_relay_id: String,
        peer_registry: Arc<PeerRegistry>,
        config: Arc<RelayConfig>,
    ) {
        let interval = Duration::from_secs(config.federation_gossip_interval_secs);
        let peer_ttl = config.federation_peer_ttl_secs;

        info!(
            "Gossip task started: interval={}s, peer_ttl={}s",
            config.federation_gossip_interval_secs, peer_ttl
        );

        loop {
            tokio::time::sleep(interval).await;

            // Build advertisement from all known peers (exclude self)
            let peers = peer_registry.all_peers();
            let advertised: Vec<AdvertisedPeer> = peers
                .iter()
                .filter(|p| p.relay_id != own_relay_id)
                .map(|p| {
                    let capacity_pct = if p.capacity_max_bytes > 0 {
                        ((p.capacity_used_bytes as f64 / p.capacity_max_bytes as f64) * 100.0) as u8
                    } else {
                        0
                    };
                    AdvertisedPeer {
                        relay_id: p.relay_id.clone(),
                        url: p.url.clone(),
                        capacity_pct,
                        last_seen_secs: p.last_seen_secs,
                    }
                })
                .collect();

            if advertised.is_empty() {
                debug!("Gossip tick: no peers to advertise");
            } else {
                // Send to all connected peers
                let connected = peer_registry.connected_peers();
                let envelope = create_federation_envelope(FederationPayload::PeerAdvertisement {
                    peers: advertised.clone(),
                });

                match encode_federation_message(&envelope) {
                    Ok(encoded) => {
                        let mut sent_count = 0;
                        for peer in &connected {
                            if peer.relay_id == own_relay_id {
                                continue;
                            }
                            if let Some(sender) = &peer.sender {
                                match sender.try_send(encoded.clone()) {
                                    Ok(_) => sent_count += 1,
                                    Err(e) => {
                                        warn!("Failed to send gossip to {}: {}", peer.relay_id, e);
                                    }
                                }
                            }
                        }
                        debug!(
                            "Gossip tick: advertised {} peers to {} connected peers",
                            advertised.len(),
                            sent_count
                        );
                    }
                    Err(e) => {
                        warn!("Failed to encode gossip advertisement: {}", e);
                    }
                }
            }

            // Clean up stale discovered peers
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let removed = peer_registry.remove_stale_peers(now_secs, peer_ttl);
            if removed > 0 {
                info!("Gossip cleanup: removed {} stale discovered peers", removed);
            }
        }
    }

    /// Processes an incoming peer advertisement from a peer.
    ///
    /// Merges advertised peers into the registry, ignoring:
    /// - Our own relay ID
    /// - Peers already known with fresher timestamps
    ///
    /// Returns the number of newly discovered peers.
    pub fn process_peer_advertisement(
        own_relay_id: &str,
        peer_registry: &PeerRegistry,
        advertised_peers: &[AdvertisedPeer],
    ) -> usize {
        let mut new_count = 0;

        for peer in advertised_peers {
            // Never add ourselves
            if peer.relay_id == own_relay_id {
                continue;
            }

            let added = peer_registry.add_discovered_peer(
                &peer.relay_id,
                &peer.url,
                peer.capacity_pct,
                peer.last_seen_secs,
            );

            if added {
                new_count += 1;
                info!(
                    "Gossip: discovered new peer {} at {}",
                    peer.relay_id, peer.url
                );
            }
        }

        new_count
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::peer_registry::{PeerInfo, PeerOrigin, PeerStatus};

        fn make_configured_peer(relay_id: &str) -> PeerInfo {
            PeerInfo {
                relay_id: relay_id.to_string(),
                url: format!("ws://{}:8080", relay_id),
                capacity_used_bytes: 100,
                capacity_max_bytes: 1000,
                status: PeerStatus::Connected,
                sender: None,
                origin: PeerOrigin::Configured,
                last_seen_secs: 1000,
            }
        }

        #[test]
        fn test_process_advertisement_new_peers() {
            let registry = PeerRegistry::new(0.95);
            registry.register_peer(make_configured_peer("existing"));

            let advertised = vec![
                AdvertisedPeer {
                    relay_id: "new-peer-1".to_string(),
                    url: "ws://new-1:8080".to_string(),
                    capacity_pct: 30,
                    last_seen_secs: 2000,
                },
                AdvertisedPeer {
                    relay_id: "new-peer-2".to_string(),
                    url: "ws://new-2:8080".to_string(),
                    capacity_pct: 60,
                    last_seen_secs: 2500,
                },
            ];

            let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
            assert_eq!(new_count, 2);
            assert_eq!(registry.peer_count(), 3); // existing + 2 new
        }

        #[test]
        fn test_process_advertisement_ignores_self() {
            let registry = PeerRegistry::new(0.95);

            let advertised = vec![AdvertisedPeer {
                relay_id: "my-relay".to_string(),
                url: "ws://my-relay:8080".to_string(),
                capacity_pct: 50,
                last_seen_secs: 2000,
            }];

            let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
            assert_eq!(new_count, 0);
            assert_eq!(registry.peer_count(), 0);
        }

        #[test]
        fn test_process_advertisement_updates_existing() {
            let registry = PeerRegistry::new(0.95);
            registry.register_peer(make_configured_peer("existing"));

            let advertised = vec![AdvertisedPeer {
                relay_id: "existing".to_string(),
                url: "ws://existing:8080".to_string(),
                capacity_pct: 80,
                last_seen_secs: 5000,
            }];

            let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
            assert_eq!(new_count, 0); // not a new peer
            assert_eq!(registry.peer_count(), 1);

            // But last_seen should be updated
            let peers = registry.all_peers();
            assert_eq!(peers[0].last_seen_secs, 5000);
        }

        #[test]
        fn test_process_advertisement_dedup() {
            let registry = PeerRegistry::new(0.95);

            let advertised = vec![
                AdvertisedPeer {
                    relay_id: "peer-a".to_string(),
                    url: "ws://peer-a:8080".to_string(),
                    capacity_pct: 30,
                    last_seen_secs: 2000,
                },
                // Same peer advertised again (duplicate)
                AdvertisedPeer {
                    relay_id: "peer-a".to_string(),
                    url: "ws://peer-a:8080".to_string(),
                    capacity_pct: 40,
                    last_seen_secs: 2500,
                },
            ];

            let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
            // First add is new, second is update
            assert_eq!(new_count, 1);
            assert_eq!(registry.peer_count(), 1);
        }

        #[test]
        fn test_process_advertisement_empty() {
            let registry = PeerRegistry::new(0.95);
            let new_count = process_peer_advertisement("my-relay", &registry, &[]);
            assert_eq!(new_count, 0);
        }

        #[test]
        fn test_stale_peer_cleanup_via_registry() {
            let registry = PeerRegistry::new(0.95);
            // Configured peer at t=0
            let mut configured = make_configured_peer("configured");
            configured.last_seen_secs = 0;
            registry.register_peer(configured);

            // Discovered peer at t=100
            registry.add_discovered_peer("old-discovered", "ws://old:8080", 50, 100);
            // Discovered peer at t=9500
            registry.add_discovered_peer("new-discovered", "ws://new:8080", 50, 9500);

            // Now is t=10000, TTL is 3600
            let removed = registry.remove_stale_peers(10000, 3600);
            // old-discovered: age=9900 >= 3600 → removed
            // new-discovered: age=500 < 3600 → kept
            // configured: always kept
            assert_eq!(removed, 1);
            assert_eq!(registry.peer_count(), 2);
        }
    }
}
