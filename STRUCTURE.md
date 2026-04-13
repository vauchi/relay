<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Code Structure

## Module Organization

```text
vauchi-relay/
├── src/
│   ├── main.rs                  # Server entry point, TCP listener, federation WS routing
│   ├── lib.rs                   # Module declarations
│   ├── config.rs                # Configuration management (incl. federation)
│   ├── handler/                 # Shared handler utilities
│   │   ├── mod.rs               # Re-exports NonceTracker
│   │   ├── nonce.rs             # Nonce tracking for replay prevention
│   │   └── verify.rs            # Ed25519 purge signature verification
│   ├── http_api.rs              # HTTP v2 REST API (/v2/* endpoints)
│   ├── http.rs                  # Health/metrics HTTP server
│   ├── storage.rs               # Blob storage (SQLite)
│   ├── recovery_storage.rs      # Recovery proof storage (SQLite)
│   ├── rate_limit.rs            # Per-client rate limiting
│   ├── ohttp_gateway.rs         # OHTTP privacy gateway
│   ├── escrow.rs                # Escrow store for gated blob exchange
│   ├── exchange_broker.rs       # Short-code exchange broker
│   ├── noise_key.rs             # Noise keypair management
│   ├── noise_transport.rs       # Noise NK transport helpers
│   ├── federation_protocol.rs   # Relay-to-relay wire protocol types
│   ├── federation_handler.rs    # Incoming federation connection handler
│   ├── federation_connector.rs  # Outgoing federation + OffloadManager
│   ├── federation_tls.rs        # mTLS for federation
│   ├── forwarding_hints.rs      # Forwarding hint storage (SQLite)
│   ├── integrity.rs             # SHA-256 blob integrity hashing
│   ├── peer_registry.rs         # Federation peer tracking
│   ├── connection_limit.rs      # TCP connection limiting
│   ├── padding.rs               # OHTTP response padding
│   ├── url_validation.rs        # URL format validation
│   ├── version_policy.rs        # Client version enforcement
│   ├── jitter.rs                # Delivery timing jitter
│   └── metrics.rs               # Prometheus metrics
└── Cargo.toml
```

## Components

### `main.rs` - Server Entry Point

Server startup, TCP listener. Routes connections to:

- Federation WebSocket handler (`/federation` path)
- HTTP health checks (`/health`, `/up`, `/ready`)
- 426 Upgrade Required for non-federation WebSocket upgrades

### `http_api.rs` - HTTP v2 REST API

All client communication uses `/v2/*` endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/v2/send` | Store encrypted blob |
| `/v2/fetch` | Retrieve pending blobs by mailbox tokens |
| `/v2/ack` | Acknowledge/delete a blob |
| `/v2/register` | Register mailbox tokens |
| `/v2/purge` | Authenticated purge (Ed25519 signed) |
| `/v2/recovery/store` | Store recovery proof |
| `/v2/recovery/query` | Batch query recovery proofs |
| `/v2/exchange/offer` | Create exchange offer (6-digit code) |
| `/v2/exchange/claim` | Claim exchange with response payload |
| `/v2/exchange/complete` | Complete exchange handshake |
| `/v2/ohttp-key` | Get OHTTP public key config |
| `/v2/ohttp` | OHTTP-encapsulated request (wraps any action above) |

### `handler/` - Shared Handler Utilities

| Module | Purpose |
|--------|---------|
| `nonce.rs` | `NonceTracker` — replay prevention for purge tokens |
| `verify.rs` | `verify_purge_ed25519` — signature verification for purge |

### `storage.rs` - Blob Storage

SQLite-backed blob store with TTL expiration.

### `recovery_storage.rs` - Recovery Proof Storage

SQLite-backed storage for recovery proofs, keyed by hash(old_pk).

### Federation Modules

| Module | Purpose |
|--------|---------|
| `federation_protocol.rs` | Wire protocol types (4-byte BE + JSON framing) |
| `federation_handler.rs` | Incoming WebSocket connections from peer relays |
| `federation_connector.rs` | Outgoing connections + `OffloadManager` |
| `federation_tls.rs` | mTLS certificate handling |
| `forwarding_hints.rs` | Routing hints for offloaded blobs |
| `peer_registry.rs` | Peer capacity and status tracking |

## Message Flow

```text
Client A                    Relay                     Client B
   │                          │                          │
   │── POST /v2/send ────────►│  (store for B)           │
   │◄── 200 {blob_id} ────────│                          │
   │                          │                          │
   │                          │◄── POST /v2/fetch ───────│
   │                          │──── 200 {blobs} ────────►│
   │                          │◄── POST /v2/ack ─────────│
   │                          │                          │
```
