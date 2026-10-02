// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Gossip-based peer discovery.
//!
//! Periodic gossip task that advertises known peers to all connected
//! federation peers. On receiving a peer advertisement, new peers are
//! merged into the peer registry with a TTL. Stale peers are cleaned
//! up periodically.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use super::{PeerInfo, PeerRegistry};
use crate::federation_protocol::{
    AdvertisedPeer, FederationPayload, create_federation_envelope, encode_federation_message,
};

/// What one gossip round did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipRound {
    /// Peers named in the advertisement.
    pub advertised: usize,
    /// Connected peers the advertisement was handed to.
    pub sent: usize,
    /// Stale discovered peers dropped from the registry.
    pub removed_stale: usize,
}

/// Runs a gossip round every `interval`, forever.
pub async fn run_gossip_task(
    own_relay_id: String,
    peer_registry: Arc<PeerRegistry>,
    interval: Duration,
    peer_ttl_secs: u64,
) {
    info!(
        "Gossip task started: interval={}s, peer_ttl={}s",
        interval.as_secs(),
        peer_ttl_secs
    );

    loop {
        tokio::time::sleep(interval).await;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let round = run_gossip_round(&own_relay_id, &peer_registry, peer_ttl_secs, now_secs);

        debug!(
            "Gossip tick: advertised {} peers to {} connected peers",
            round.advertised, round.sent
        );
        if round.removed_stale > 0 {
            info!(
                "Gossip cleanup: removed {} stale discovered peers",
                round.removed_stale
            );
        }
    }
}

/// Runs one gossip round as of `now_secs`: advertises every known peer
/// except ourselves to each connected peer, then drops discovered peers
/// not seen within `peer_ttl_secs`.
pub fn run_gossip_round(
    own_relay_id: &str,
    peer_registry: &PeerRegistry,
    peer_ttl_secs: u64,
    now_secs: u64,
) -> GossipRound {
    let advertised: Vec<AdvertisedPeer> = peer_registry
        .all_peers()
        .iter()
        .filter(|p| p.relay_id != own_relay_id)
        .map(|p| AdvertisedPeer {
            relay_id: p.relay_id.clone(),
            url: p.url.clone(),
            capacity_pct: capacity_pct(p),
            last_seen_secs: p.last_seen_secs,
        })
        .collect();

    let sent = if advertised.is_empty() {
        0
    } else {
        send_advertisement(own_relay_id, peer_registry, &advertised)
    };

    GossipRound {
        advertised: advertised.len(),
        sent,
        removed_stale: peer_registry.remove_stale_peers(now_secs, peer_ttl_secs),
    }
}

fn capacity_pct(peer: &PeerInfo) -> u8 {
    if peer.capacity_max_bytes > 0 {
        ((peer.capacity_used_bytes as f64 / peer.capacity_max_bytes as f64) * 100.0) as u8
    } else {
        0
    }
}

/// Hands the advertisement to every connected peer but ourselves;
/// returns how many accepted it.
fn send_advertisement(
    own_relay_id: &str,
    peer_registry: &PeerRegistry,
    advertised: &[AdvertisedPeer],
) -> usize {
    let envelope = create_federation_envelope(FederationPayload::PeerAdvertisement {
        peers: advertised.to_vec(),
    });
    let encoded = match encode_federation_message(&envelope) {
        Ok(encoded) => encoded,
        Err(e) => {
            warn!("Failed to encode gossip advertisement: {}", e);
            return 0;
        }
    };

    let mut sent = 0;
    for peer in peer_registry.connected_peers() {
        if peer.relay_id == own_relay_id {
            continue;
        }
        if let Some(sender) = &peer.sender {
            match sender.try_send(encoded.clone()) {
                Ok(_) => sent += 1,
                Err(e) => {
                    warn!("Failed to send gossip to {}: {}", peer.relay_id, e);
                }
            }
        }
    }
    sent
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

// INLINE_TEST_REQUIRED: Tests gossip processing logic using internal PeerRegistry methods
#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_registry::{PeerInfo, PeerOrigin, PeerStatus};

    fn make_configured_peer(relay_id: &str) -> PeerInfo {
        PeerInfo {
            relay_id: relay_id.to_string(),
            url: format!("https://{}:8080", relay_id),
            capacity_used_bytes: 100,
            capacity_max_bytes: 1000,
            status: PeerStatus::Connected,
            sender: None,
            origin: PeerOrigin::Configured,
            last_seen_secs: 1000,
        }
    }

    // @internal
    #[test]
    fn test_process_advertisement_new_peers() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_configured_peer("existing"));

        let advertised = vec![
            AdvertisedPeer {
                relay_id: "new-peer-1".to_string(),
                url: "https://new-1:8080".to_string(),
                capacity_pct: 30,
                last_seen_secs: 2000,
            },
            AdvertisedPeer {
                relay_id: "new-peer-2".to_string(),
                url: "https://new-2:8080".to_string(),
                capacity_pct: 60,
                last_seen_secs: 2500,
            },
        ];

        let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
        assert_eq!(new_count, 2);
        assert_eq!(registry.peer_count(), 3); // existing + 2 new
    }

    // @internal
    #[test]
    fn test_process_advertisement_ignores_self() {
        let registry = PeerRegistry::new(0.95);

        let advertised = vec![AdvertisedPeer {
            relay_id: "my-relay".to_string(),
            url: "https://my-relay:8080".to_string(),
            capacity_pct: 50,
            last_seen_secs: 2000,
        }];

        let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
        assert_eq!(new_count, 0);
        assert_eq!(registry.peer_count(), 0);
    }

    // @internal
    #[test]
    fn test_process_advertisement_updates_existing() {
        let registry = PeerRegistry::new(0.95);
        registry.register_peer(make_configured_peer("existing"));

        let advertised = vec![AdvertisedPeer {
            relay_id: "existing".to_string(),
            url: "https://existing:8080".to_string(),
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

    // @internal
    #[test]
    fn test_process_advertisement_dedup() {
        let registry = PeerRegistry::new(0.95);

        let advertised = vec![
            AdvertisedPeer {
                relay_id: "peer-a".to_string(),
                url: "https://peer-a:8080".to_string(),
                capacity_pct: 30,
                last_seen_secs: 2000,
            },
            // Same peer advertised again (duplicate)
            AdvertisedPeer {
                relay_id: "peer-a".to_string(),
                url: "https://peer-a:8080".to_string(),
                capacity_pct: 40,
                last_seen_secs: 2500,
            },
        ];

        let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
        // First add is new, second is update
        assert_eq!(new_count, 1);
        assert_eq!(registry.peer_count(), 1);
    }

    // Trace: codebase-review-tracker item #133
    // @internal
    #[test]
    fn test_process_advertisement_rejects_ssrf_urls() {
        let registry = PeerRegistry::new(0.95);

        let advertised = vec![
            AdvertisedPeer {
                relay_id: "ssrf-peer".to_string(),
                url: "https://10.0.0.1:8080".to_string(),
                capacity_pct: 30,
                last_seen_secs: 2000,
            },
            AdvertisedPeer {
                relay_id: "good-peer".to_string(),
                url: "https://203.0.113.50:443".to_string(),
                capacity_pct: 20,
                last_seen_secs: 2000,
            },
        ];

        let new_count = process_peer_advertisement("my-relay", &registry, &advertised);
        assert_eq!(new_count, 1, "Only the public-IP peer should be added");
        assert_eq!(registry.peer_count(), 1);
        let peers = registry.all_peers();
        assert_eq!(peers[0].relay_id, "good-peer");
    }

    // @internal
    #[test]
    fn test_process_advertisement_empty() {
        let registry = PeerRegistry::new(0.95);
        let new_count = process_peer_advertisement("my-relay", &registry, &[]);
        assert_eq!(new_count, 0);
    }

    // @internal
    #[test]
    fn test_stale_peer_cleanup_via_registry() {
        let registry = PeerRegistry::new(0.95);
        // Configured peer at t=0
        let mut configured = make_configured_peer("configured");
        configured.last_seen_secs = 0;
        registry.register_peer(configured);

        // Discovered peer at t=100
        registry.add_discovered_peer("old-discovered", "https://old:8080", 50, 100);
        // Discovered peer at t=9500
        registry.add_discovered_peer("new-discovered", "https://new:8080", 50, 9500);

        // Now is t=10000, TTL is 3600
        let removed = registry.remove_stale_peers(10000, 3600);
        // old-discovered: age=9900 >= 3600 → removed
        // new-discovered: age=500 < 3600 → kept
        // configured: always kept
        assert_eq!(removed, 1);
        assert_eq!(registry.peer_count(), 2);
    }

    fn connected_peer_with_inbox(
        relay_id: &str,
    ) -> (PeerInfo, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (sender, inbox) = tokio::sync::mpsc::channel(4);
        let mut peer = make_configured_peer(relay_id);
        peer.sender = Some(sender);
        (peer, inbox)
    }

    /// `(relay_id, capacity_pct, last_seen_secs)` of each advertised peer, by id.
    fn advertised_in(message: &[u8]) -> Vec<(String, u8, u64)> {
        let envelope = crate::federation_protocol::decode_federation_message(message).unwrap();
        let FederationPayload::PeerAdvertisement { peers } = envelope.payload else {
            panic!("expected a PeerAdvertisement, got {:?}", envelope.payload);
        };
        let mut advertised: Vec<(String, u8, u64)> = peers
            .into_iter()
            .map(|p| (p.relay_id, p.capacity_pct, p.last_seen_secs))
            .collect();
        advertised.sort();
        advertised
    }

    // @internal
    #[test]
    fn test_gossip_round_advertises_every_peer_but_ourselves_to_connected_peers() {
        let registry = PeerRegistry::new(0.95);
        let (ourselves, mut our_inbox) = connected_peer_with_inbox("my-relay");
        registry.register_peer(ourselves);
        let (mut quarter_full, mut peer_inbox) = connected_peer_with_inbox("peer-a");
        quarter_full.capacity_used_bytes = 250;
        registry.register_peer(quarter_full);
        let mut unknown_capacity = make_configured_peer("peer-b");
        unknown_capacity.capacity_used_bytes = 5;
        unknown_capacity.capacity_max_bytes = 0;
        unknown_capacity.status = PeerStatus::Disconnected;
        registry.register_peer(unknown_capacity);

        let round = run_gossip_round("my-relay", &registry, 3600, 1000);

        assert_eq!(
            round,
            GossipRound {
                advertised: 2,
                sent: 1,
                removed_stale: 0
            }
        );
        assert_eq!(
            advertised_in(&peer_inbox.try_recv().unwrap()),
            vec![
                ("peer-a".to_string(), 25, 1000),
                ("peer-b".to_string(), 0, 1000)
            ]
        );
        assert!(our_inbox.try_recv().is_err());
    }

    // @internal
    #[test]
    fn test_gossip_round_with_nothing_to_advertise_sends_nothing() {
        let registry = PeerRegistry::new(0.95);
        let (ourselves, mut our_inbox) = connected_peer_with_inbox("my-relay");
        registry.register_peer(ourselves);

        let round = run_gossip_round("my-relay", &registry, 3600, 1000);

        assert_eq!(
            round,
            GossipRound {
                advertised: 0,
                sent: 0,
                removed_stale: 0
            }
        );
        assert!(our_inbox.try_recv().is_err());
    }

    // @internal
    #[test]
    fn test_gossip_round_drops_stale_discovered_peers() {
        let registry = PeerRegistry::new(0.95);
        registry.add_discovered_peer("stale", "https://stale:8080", 50, 100);

        let round = run_gossip_round("my-relay", &registry, 3600, 5000);

        assert_eq!(
            round,
            GossipRound {
                advertised: 1,
                sent: 0,
                removed_stale: 1
            }
        );
        assert_eq!(registry.peer_count(), 0);
    }

    // Paused clock: the runtime jumps to the task's next timer as soon
    // as everything is idle, so the interval costs no real time (CC-06).
    // @internal
    #[tokio::test(start_paused = true)]
    async fn test_gossip_task_runs_a_round_each_interval() {
        let registry = Arc::new(PeerRegistry::new(0.95));
        let (peer, mut peer_inbox) = connected_peer_with_inbox("peer-a");
        registry.register_peer(peer);
        let task = tokio::spawn(run_gossip_task(
            "my-relay".to_string(),
            registry,
            Duration::from_secs(120),
            3600,
        ));

        // Bounded in virtual time, so a task that never sends fails the
        // test instead of hanging it.
        let two_rounds = tokio::time::timeout(Duration::from_secs(600), async {
            let first = peer_inbox.recv().await.unwrap();
            let second = peer_inbox.recv().await.unwrap();
            (first, second)
        })
        .await;
        task.abort();
        let (first, second) = two_rounds.unwrap();

        let expected = vec![("peer-a".to_string(), 10, 1000)];
        assert_eq!(advertised_in(&first), expected);
        assert_eq!(advertised_in(&second), expected);
    }
}
