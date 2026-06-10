<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

> **Mirror:** This repo is a read-only mirror of [gitlab.com/vauchi/relay](https://gitlab.com/vauchi/relay). Please open issues and merge requests there.

[![Pipeline](https://img.shields.io/endpoint?url=https://vauchi.gitlab.io/relay/badges/pipeline.json&label=pipeline)](https://gitlab.com/vauchi/relay/-/pipelines)
[![Coverage](https://img.shields.io/endpoint?url=https://vauchi.gitlab.io/relay/badges/coverage.json&label=coverage)](https://gitlab.com/vauchi/relay/-/pipelines)
[![REUSE](https://api.reuse.software/badge/gitlab.com/vauchi/relay)](https://api.reuse.software/info/gitlab.com/vauchi/relay)

> [!NOTE]
> **You're early — and that's the point.** Vauchi is pre-alpha and
> under heavy development: not yet ready for production, and APIs may
> change without notice. If you're here now, you can help shape it —
> try it, break it, and tell us what's missing.

# Vauchi Relay

Lightweight relay server for Vauchi - stores and forwards
encrypted blobs between clients via HTTP v2 REST API.

## Overview

The relay server is an oblivious privacy-preserving message broker. It:

- Provides an HTTP v2 REST API for blob storage and retrieval
- Supports OHTTP (RFC 9458) for IP-level privacy
- Stores encrypted messages for offline recipients
- Automatically expires old messages (120 days default)
- Rate limits clients to prevent abuse
- Federates with peer relays for redundancy

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
| `RELAY_FEDERATION_PEERS` | _(empty)_ | Comma-separated peer relay URLs (e.g. `https://relay-b:8443,https://relay-c:8443`) — mTLS-HTTP (ADR-052) |
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

Clients communicate via HTTP v2 REST API (`/v2/*` endpoints).
All requests/responses are JSON. Binary data (ciphertext, proofs)
is base64-encoded. Key hashes are hex-encoded.

### Client Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v2/send` | POST | Store encrypted blob for recipient |
| `/v2/fetch` | POST | Retrieve pending blobs by mailbox tokens |
| `/v2/ack` | POST | Acknowledge/delete a blob |
| `/v2/register` | POST | Register mailbox tokens |
| `/v2/purge` | POST | Authenticated purge (Ed25519 signed) |
| `/v2/recovery/store` | POST | Store recovery proof |
| `/v2/recovery/query` | POST | Batch query recovery proofs |
| `/v2/exchange/offer` | POST | Create exchange offer (6-digit code) |
| `/v2/exchange/claim` | POST | Claim exchange with response |
| `/v2/exchange/complete` | POST | Complete exchange handshake |
| `/v2/ohttp-key` | GET | OHTTP public key config |
| `/v2/ohttp` | POST | OHTTP-encapsulated request |

All endpoints above are also routable via OHTTP for IP privacy.

## Architecture

See `STRUCTURE.md` for full module listing.

### Components

- **HTTP v2 API**: REST endpoints for all client
  operations (blob CRUD, purge, recovery, exchange)
- **OHTTP Gateway**: RFC 9458 privacy layer
- **Storage**: SQLite-backed blob store with TTL
- **Recovery Storage**: SQLite-backed recovery proofs
- **Rate Limiter**: Token bucket algorithm per client ID
- **Federation (mTLS-HTTP)**: Serves `/v2/federation/*`
  on the dedicated mTLS listener (ADR-052)
- **Federation Connector**: POSTs blobs to peer relays
  over mTLS-HTTP on demand
- **OffloadManager**: Monitors storage usage and
  offloads blobs when above threshold

## Operational Capabilities

Everything listed below is **implemented and tested**
— not planned.

### Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/v2/*` | 8080 (main) | Client HTTP v2 API |
| `/health` | 8080 (main) | Liveness (no info leak) |
| `/v2/federation/*` | mTLS listener | Federation (mTLS-HTTP) |
| `/health` | 8081 (ops) | Health check |
| `/metrics` | 8081 (ops) | Prometheus (optional auth) |
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
- Ed25519 signature verification + nonce replay
  protection (±60s window) for purge operations
- OHTTP gateway (RFC 9458) for client IP privacy
- SSRF validation on federation peer URLs
  (blocks private/loopback/link-local)
- mTLS (mutual client+server certs) for federation transport (ADR-052)

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

- **Oblivious relay**: sees encrypted blobs only,
  sender/recipient identity minimized
- **Rate limiting**: per-client, per-peer, per-recovery
- **TLS mandatory**: startup refuses without
  `RELAY_TLS_VERIFIED=true` on non-localhost
- **OHTTP**: IP-level privacy for client requests
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
2. When over the offload threshold, the relay POSTs blobs
   to peers over mTLS-HTTP (`/v2/federation/message`)
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
# Federation requires mTLS — set RELAY_FEDERATION_TLS_CERT/KEY/CA on
# both relays (peer URLs are https:// to the mTLS listener).
# Relay A
RELAY_FEDERATION_ENABLED=true \
RELAY_FEDERATION_PEERS=https://relay-b:8443 \
RELAY_LISTEN_ADDR=0.0.0.0:8080 \
vauchi-relay

# Relay B
RELAY_FEDERATION_ENABLED=true \
RELAY_FEDERATION_PEERS=https://relay-a:8443 \
RELAY_LISTEN_ADDR=0.0.0.0:8080 \
vauchi-relay
```

### Privacy Guarantees

Federation preserves the oblivious privacy-preserving design:

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
