<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Code Structure

## Module Organization

```
vauchi-relay/
├── src/
│   ├── main.rs                  # Server entry point, path-based WS routing
│   ├── config.rs                # Configuration management (incl. federation)
│   ├── handler.rs               # Client WebSocket connection handler
│   ├── storage.rs               # Blob storage (Memory + SQLite)
│   ├── rate_limit.rs            # Per-client rate limiting
│   ├── federation_protocol.rs   # Relay-to-relay wire protocol types
│   ├── federation_handler.rs    # Incoming federation connection handler
│   ├── federation_connector.rs  # Outgoing federation + OffloadManager
│   ├── forwarding_hints.rs      # Forwarding hint storage (Memory + SQLite)
│   ├── integrity.rs             # SHA-256 blob integrity hashing
│   └── peer_registry.rs         # Federation peer tracking
└── Cargo.toml                   # Crate configuration
```

## Components

### `main.rs` - Server Entry Point

Server startup, WebSocket listener, and connection dispatch.

| Function | Purpose |
|----------|---------|
| `main` | Async entry point, config loading, server start |
| `handle_connection` | Accepts WebSocket upgrade, spawns handler |

### `config.rs` - Configuration

Environment-based configuration.

| Item | Purpose |
|------|---------|
| `Config` | Server settings (port, limits, TTL) |
| `Config::from_env` | Load from environment variables |

### `handler.rs` - WebSocket Handler

Per-connection message processing.

| Function | Purpose |
|----------|---------|
| `ConnectionHandler::new` | Create handler for new connection |
| `handle_message` | Route incoming messages by type |
| `handle_handshake` | Process client authentication |
| `handle_encrypted_update` | Store and forward encrypted blobs |
| `deliver_pending` | Send stored messages to connected client |

### `storage.rs` - Blob Storage

Thread-safe in-memory storage with expiration.

| Item | Purpose |
|------|---------|
| `BlobStore` | Concurrent hashmap for blobs |
| `store` | Save blob with TTL |
| `retrieve` | Get blobs for recipient |
| `cleanup` | Remove expired blobs |

### `rate_limit.rs` - Rate Limiting

Token bucket algorithm per client.

| Item | Purpose |
|------|---------|
| `RateLimiter` | Per-client rate limit state |
| `check` | Verify client hasn't exceeded limit |
| `record` | Track client message |

### `federation_protocol.rs` - Wire Protocol

Relay-to-relay message types (same 4-byte BE length prefix + JSON framing as client protocol).

| Item | Purpose |
|------|---------|
| `FederationEnvelope` | Top-level message wrapper (version, message_id, timestamp, payload) |
| `FederationPayload` | Enum: PeerHandshake, PeerHandshakeAck, OffloadBlob, OffloadAck, CapacityReport, DrainNotice, DrainAck |
| `encode_federation_message` | Serialize envelope to wire format |
| `decode_federation_message` | Deserialize wire bytes to envelope |

### `federation_handler.rs` - Incoming Federation

Handles WebSocket connections from peer relays on the `/federation` endpoint.

| Item | Purpose |
|------|---------|
| `FederationDeps` | Shared dependencies (storage, hints, registry, config) |
| `handle_federation_connection` | Process peer handshake, receive offloaded blobs, handle drain |

### `federation_connector.rs` - Outgoing Federation

Maintains persistent connections to configured peer relays.

| Item | Purpose |
|------|---------|
| `maintain_peer_connection` | Connect to peer, reconnect with exponential backoff |
| `OffloadManager` | Check storage usage, offload oldest blobs to peers |

### `forwarding_hints.rs` - Offload Tracking

Stores routing_id to peer relay mappings so clients can find offloaded blobs.

| Item | Purpose |
|------|---------|
| `ForwardingHintStore` | Trait: store, get, remove, cleanup hints |
| `MemoryForwardingHintStore` | In-memory implementation (tests) |
| `SqliteForwardingHintStore` | SQLite implementation (separate `federation.db`) |

### `integrity.rs` - Blob Verification

SHA-256 hashing for blob integrity during federation transfer.

| Item | Purpose |
|------|---------|
| `compute_integrity_hash` | SHA-256 hash of blob data (ciphertext) |
| `verify_integrity_hash` | Compare computed hash against expected |

### `peer_registry.rs` - Peer Tracking

Tracks connected federation peers and their capacity.

| Item | Purpose |
|------|---------|
| `PeerRegistry` | Thread-safe peer state (capacity, status, sender channels) |
| `PeerInfo` | Per-peer metadata |
| `PeerStatus` | Connected, Draining, or Disconnected |

## Message Flow

```
Client A                    Relay                     Client B
   │                          │                          │
   │──── Handshake ──────────►│                          │
   │◄─── Ack ─────────────────│                          │
   │                          │                          │
   │──── EncryptedUpdate ────►│  (store for B)           │
   │◄─── Ack ─────────────────│                          │
   │                          │                          │
   │                          │◄──── Handshake ──────────│
   │                          │───── Ack ───────────────►│
   │                          │───── EncryptedUpdate ───►│
   │                          │                          │
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `tokio-tungstenite` | WebSocket support |
| `serde` | JSON serialization |
| `rusqlite` | SQLite storage backend |
| `ring` | SHA-256 integrity hashing (federation) |
| `tracing` | Logging |
