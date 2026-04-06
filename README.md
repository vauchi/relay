<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

> **Mirror:** This repo is a read-only mirror of [gitlab.com/vauchi/relay](https://gitlab.com/vauchi/relay). Please open issues and merge requests there.

[![Pipeline](https://img.shields.io/endpoint?url=https://vauchi.gitlab.io/relay/badges/pipeline.json&label=pipeline)](https://gitlab.com/vauchi/relay/-/pipelines)
[![Coverage](https://img.shields.io/endpoint?url=https://vauchi.gitlab.io/relay/badges/coverage.json&label=coverage)](https://gitlab.com/vauchi/relay/-/pipelines)
[![REUSE](https://api.reuse.software/badge/gitlab.com/vauchi/relay)](https://api.reuse.software/info/gitlab.com/vauchi/relay)

> [!WARNING]
> **Pre-Alpha Software** - This project is under heavy
> development and not ready for production use.
> APIs may change without notice. Use at your own risk.

# Vauchi Relay

Lightweight WebSocket relay server for Vauchi - stores
and forwards encrypted blobs between clients.

## Overview

The relay server is a zero-knowledge message broker. It:

- Accepts WebSocket connections from Vauchi clients
- Stores encrypted messages for offline recipients
- Forwards messages when recipients connect
- Automatically expires old messages (30 days default)
- Rate limits clients to prevent abuse

**Privacy**: The server only sees encrypted blobs.
It cannot read message contents, identify contacts,
or access any user data.

## Installation

```bash
cargo build -p vauchi-relay --release
```

The binary will be at `target/release/vauchi-relay`.

## Usage

```bash
# Start with defaults (port 8080)
vauchi-relay

# Or run via cargo
cargo run -p vauchi-relay
```

The server listens on `0.0.0.0:8080` by default.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_LISTEN_ADDR` | `0.0.0.0:8080` | Address to listen on |
| `RELAY_MAX_MESSAGE_SIZE` | `1048576` | Maximum message size in bytes (1 MB) |
| `RELAY_BLOB_TTL_SECS` | `10368000` | Blob expiration time in seconds (120 days) |
| `RELAY_RATE_LIMIT` | `60` | Messages per minute per client |
| `RELAY_CLEANUP_INTERVAL` | `3600` | Cleanup interval in seconds (1 hour) |
| `RELAY_STORAGE_BACKEND` | `sqlite` | Storage backend: `sqlite` (persistent) or `memory` |
| `RELAY_DATA_DIR` | `./data` | Directory for SQLite database file |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

### Federation Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_FEDERATION_ENABLED` | `false` | Enable federation with peer relays |
| `RELAY_FEDERATION_PEERS` | _(empty)_ | Comma-separated peer relay URLs (e.g. `ws://relay-b:8080,ws://relay-c:8080`) |
| `RELAY_FEDERATION_RELAY_ID` | _(auto)_ | Stable relay identifier (auto-generated and persisted to `{data_dir}/relay_id`) |
| `RELAY_MAX_STORAGE_BYTES` | `1073741824` | Maximum storage capacity in bytes (1 GB) |
| `RELAY_FEDERATION_OFFLOAD_THRESHOLD` | `0.80` | Start offloading when storage exceeds this ratio |
| `RELAY_FEDERATION_OFFLOAD_REFUSE` | `0.95` | Refuse incoming offloads above this ratio |
| `RELAY_FEDERATION_DRAIN_TIMEOUT` | `300` | Drain timeout in seconds for graceful shutdown |
| `RELAY_FEDERATION_PEER_TIMEOUT` | `30` | Peer handshake timeout in seconds |
| `RELAY_FEDERATION_CAPACITY_INTERVAL` | `60` | Capacity check interval in seconds |

**Note:** The 120-day TTL balances storage efficiency
with allowing infrequent sync. SQLite storage (default)
persists messages across server restarts.

## Protocol

The relay uses a simple JSON protocol over WebSocket binary frames.

### Message Format

Messages are length-prefixed JSON:

```text
[4 bytes: length][JSON payload]
```

### Message Types

**Handshake** (client → server):

```json
{
  "version": 1,
  "message_id": "uuid",
  "timestamp": 1234567890,
  "payload": {
    "type": "Handshake",
    "client_id": "hex-encoded-public-key"
  }
}
```

**EncryptedUpdate** (client → server):

```json
{
  "version": 1,
  "message_id": "uuid",
  "timestamp": 1234567890,
  "payload": {
    "type": "EncryptedUpdate",
    "recipient_id": "hex-encoded-public-key",
    "ciphertext": [encrypted bytes]
  }
}
```

**Acknowledgment** (server → client):

```json
{
  "version": 1,
  "message_id": "uuid",
  "timestamp": 1234567890,
  "payload": {
    "type": "Acknowledgment",
    "message_id": "original-message-id",
    "status": "ReceivedByRelay"
  }
}
```

## Architecture

```text
vauchi-relay/
├── src/
│   ├── main.rs                  # Server entry point, WS routing
│   ├── config.rs                # Configuration management
│   ├── handler.rs               # Client WebSocket handler
│   ├── storage.rs               # Blob storage (Memory + SQLite)
│   ├── rate_limit.rs            # Per-client rate limiting
│   ├── federation_protocol.rs   # Relay-to-relay wire protocol
│   ├── federation_handler.rs    # Incoming federation connections
│   ├── federation_connector.rs  # Outgoing federation connections
│   ├── forwarding_hints.rs      # Offload tracking for clients
│   ├── integrity.rs             # SHA-256 blob verification
│   └── peer_registry.rs         # Federation peer tracking
```

### Components

- **Handler**: Manages client WebSocket connections,
  parses messages, routes to storage
- **Storage**: Thread-safe blob store with automatic
  TTL expiration (Memory or SQLite)
- **Rate Limiter**: Token bucket algorithm per client ID
- **Federation Handler**: Accepts incoming peer relay
  connections, validates and stores offloaded blobs
- **Federation Connector**: Maintains persistent
  connections to peer relays with exponential backoff
- **OffloadManager**: Monitors storage usage and
  offloads blobs when above threshold
- **Peer Registry**: Tracks connected peers, capacity,
  and communication channels
- **Forwarding Hints**: Stores routing_id to peer relay
  mappings for client retrieval

## Operational Capabilities

Everything listed below is **implemented and tested**
— not planned.

### Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/health` | 8080 (main) | Liveness (no info leak) |
| `/health` | 8081 (ops) | Health check |
| `/metrics` | 8081 (ops) | Prometheus (optional auth) |
| `/pubkey` | 8081 (ops) | Noise NK public key |
| `/build-info` | 8081 (ops) | Git SHA, ref, build time |

### Graceful Shutdown

SIGTERM/SIGINT → stop accepting → drain connections
(30s timeout) → WAL checkpoint → exit. See
`src/main.rs:610-893`.

### Rate Limiting

- Per-client: token bucket (default 60 req/min)
- Recovery queries: stricter (default 10 req/min)
- Federation: per-peer (default 300 msg/min)
- Connections: hard cap (default 1000)
- Message size: 1 MB max

### Observability

- **Logging**: `tracing` crate, text or JSON
  (`RELAY_LOG_FORMAT=json`), levels via `RUST_LOG`
- **Metrics**: 30+ Prometheus metrics (connections,
  messages, blobs, federation, rate limits, panics)
- **Privacy**: zero PII logging, no IP logging,
  routing IDs only

### Security

- TLS enforced for non-localhost (`RELAY_TLS_VERIFIED`)
- Noise NK inner encryption (defense-in-depth)
- Ed25519 signature verification + nonce replay
  protection (±60s window)
- SSRF validation on federation peer URLs
  (blocks private/loopback/link-local)
- OHTTP gateway (RFC 9458) for IP privacy
- Delivery jitter for traffic analysis resistance

### Container Image

Multi-stage build → `distroless/cc-debian12` runtime.
Non-root user. No shell. See `Dockerfile`.

### Runbooks

`deploy/RUNBOOKS.md` (618 lines): deployment, incident
response, operations, privacy-safe debugging, emergency
hotfix procedures, operator observability matrix.

## Deployment

```bash
# Docker (production)
docker build -t vauchi-relay .
docker run -d \
  -p 8080:8080 -p 127.0.0.1:8081:8081 \
  -v relay-data:/data \
  -e RELAY_TLS_VERIFIED=true \
  -e RUST_LOG=vauchi_relay=info \
  vauchi-relay
```

See `deploy/RUNBOOKS.md` for full deployment,
rolling upgrade, and rollback procedures.

## Security Considerations

- **Zero-knowledge relay**: sees encrypted blobs only
- **Rate limiting**: per-client, per-peer, per-recovery
- **TLS mandatory**: startup refuses without
  `RELAY_TLS_VERIFIED=true` on non-localhost
- **Noise NK**: inner transport encryption even if
  TLS compromised
- **SQLite storage**: persistent, WAL-backed,
  `secure_delete=ON`

## Federation

The relay supports static federation with peer relays
for redundancy and scalability. When storage exceeds a
configurable threshold (default 80%), the relay offloads
its oldest blobs to peer relays and stores forwarding
hints so clients can find their data.

### How It Works

1. Configure peer relay URLs via
   `RELAY_FEDERATION_PEERS`
2. The relay maintains persistent WebSocket connections
   to peers (`/federation` endpoint)
3. When storage exceeds the offload threshold, the
   `OffloadManager` sends blobs to peers with
   available capacity
4. Source relay stores forwarding hints
   (routing_id to peer relay mapping)
5. When clients connect, they receive forwarding hints
   alongside any pending blobs
6. Clients follow hints to retrieve offloaded blobs
   from peer relays

### Example: Two-Relay Setup

```bash
# Relay A
RELAY_FEDERATION_ENABLED=true \
RELAY_FEDERATION_PEERS=ws://relay-b:8080 \
RELAY_LISTEN_ADDR=0.0.0.0:8080 \
vauchi-relay

# Relay B
RELAY_FEDERATION_ENABLED=true \
RELAY_FEDERATION_PEERS=ws://relay-a:8080 \
RELAY_LISTEN_ADDR=0.0.0.0:8080 \
vauchi-relay
```

### Privacy Guarantees

Federation preserves zero-knowledge:

- Blobs are transferred as opaque ciphertext — peer relays cannot decrypt
- `hop_count` prevents re-offloading loops (max 1 hop)
- SHA-256 integrity hashing verifies blob data during transfer
- Forwarding hints are TTL-based and cleaned on purge
- Federation handlers never log routing IDs

## Storage Considerations

The default 120-day TTL enables users who rarely open
the app to still receive contact updates.

**Storage backends:**

- `sqlite` (default): Persistent storage, survives
  restarts, disk-based
- `memory`: Fast but volatile, lost on restart,
  RAM-based

**For production deployments:**

- Use SQLite (default) for message persistence
- Set `RELAY_DATA_DIR` to a persistent volume
- Monitor disk usage with long TTLs
- Consider backup strategy for the SQLite database

## ⚠️ Mandatory Development Rules

**TDD**: Red→Green→Refactor. Test FIRST or delete code and restart.

**Structure**: `src/` = production code only. `tests/` = tests only. Siblings, not nested.

## Support the Project

Vauchi is open source and community-funded — no VC money, no data harvesting.

- [GitHub Sponsors](https://github.com/sponsors/vauchi)
- [Liberapay](https://liberapay.com/Vauchi/donate)
- [Supporters](https://docs.vauchi.app/about/supporters/) for sponsorship tiers

## License

GPL-3.0-or-later
