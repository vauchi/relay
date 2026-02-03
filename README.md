<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

> [!WARNING]
> **Pre-Alpha Software** - This project is under heavy development and not ready for production use.
> APIs may change without notice. Use at your own risk.

# Vauchi Relay

Lightweight WebSocket relay server for Vauchi - stores and forwards encrypted blobs between clients.

## Overview

The relay server is a zero-knowledge message broker. It:

- Accepts WebSocket connections from Vauchi clients
- Stores encrypted messages for offline recipients
- Forwards messages when recipients connect
- Automatically expires old messages (24 hours default)
- Rate limits clients to prevent abuse

**Privacy**: The server only sees encrypted blobs. It cannot read message contents, identify contacts, or access any user data.

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
| `RELAY_BLOB_TTL_SECS` | `7776000` | Blob expiration time in seconds (90 days) |
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

**Note:** The 90-day TTL allows users who sync infrequently to still receive updates.
SQLite storage (default) persists messages across server restarts.

## Protocol

The relay uses a simple JSON protocol over WebSocket binary frames.

### Message Format

Messages are length-prefixed JSON:

```
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
    "sender_id": "hex-encoded-public-key",
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

```
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

- **Handler**: Manages client WebSocket connections, parses messages, routes to storage
- **Storage**: Thread-safe blob store with automatic TTL expiration (Memory or SQLite)
- **Rate Limiter**: Token bucket algorithm per client ID
- **Federation Handler**: Accepts incoming peer relay connections, validates and stores offloaded blobs
- **Federation Connector**: Maintains persistent connections to peer relays with exponential backoff
- **OffloadManager**: Monitors storage usage and offloads blobs when above threshold
- **Peer Registry**: Tracks connected peers, capacity, and communication channels
- **Forwarding Hints**: Stores routing_id to peer relay mappings for client retrieval

## Deployment

### Docker (planned)

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build -p vauchi-relay --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/vauchi-relay /usr/local/bin/
EXPOSE 8080
CMD ["vauchi-relay"]
```

### Systemd

```ini
[Unit]
Description=Vauchi Relay Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vauchi-relay
Restart=always
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

## Security Considerations

- **No Authentication**: The relay is open by design; security comes from E2E encryption
- **Rate Limiting**: Prevents abuse and DoS
- **SQLite Storage**: Messages persist across restarts (use `memory` backend for volatile storage)
- **TLS**: Deploy behind a reverse proxy (nginx, caddy) for TLS termination

## Federation

The relay supports static federation with peer relays for redundancy and scalability. When storage exceeds a configurable threshold (default 80%), the relay offloads its oldest blobs to peer relays and stores forwarding hints so clients can find their data.

### How It Works

1. Configure peer relay URLs via `RELAY_FEDERATION_PEERS`
2. The relay maintains persistent WebSocket connections to peers (`/federation` endpoint)
3. When storage exceeds the offload threshold, the `OffloadManager` sends blobs to peers with available capacity
4. Source relay stores forwarding hints (routing_id to peer relay mapping)
5. When clients connect, they receive forwarding hints alongside any pending blobs
6. Clients follow hints to retrieve offloaded blobs from peer relays

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

The default 90-day TTL enables users who rarely open the app to still receive contact updates.

**Storage backends:**
- `sqlite` (default): Persistent storage, survives restarts, disk-based
- `memory`: Fast but volatile, lost on restart, RAM-based

**For production deployments:**
- Use SQLite (default) for message persistence
- Set `RELAY_DATA_DIR` to a persistent volume
- Monitor disk usage with long TTLs
- Consider backup strategy for the SQLite database

## ⚠️ Mandatory Development Rules

**TDD**: Red→Green→Refactor. Test FIRST or delete code and restart.

**Structure**: `src/` = production code only. `tests/` = tests only. Siblings, not nested.

See [CLAUDE.md](../../CLAUDE.md) for additional mandatory rules.

## Support the Project

Vauchi is open source and community-funded — no VC money, no data harvesting.

- [GitHub Sponsors](https://github.com/sponsors/vauchi)
- [Liberapay](https://liberapay.com/Vauchi/donate)
- [SUPPORTERS.md](https://gitlab.com/vauchi/vauchi/-/blob/main/SUPPORTERS.md) for sponsorship tiers

## License

MIT
