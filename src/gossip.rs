// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Gossip-Based Peer Discovery
//!
//! Periodic gossip task that advertises known peers to all connected
//! federation peers. On receiving a peer advertisement, new peers are
//! merged into the peer registry with a TTL. Stale peers are cleaned
//! up periodically.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::federation_protocol::{
    create_federation_envelope, encode_federation_message, AdvertisedPeer, FederationPayload,
};
use crate::peer_registry::PeerRegistry;

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
