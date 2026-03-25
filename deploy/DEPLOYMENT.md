<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vauchi Relay Deployment Guide

This guide covers deploying the Vauchi Relay server in production.

## Overview

The relay server provides:
- **WebSocket endpoint** (port 8080) - Encrypted blob storage and delivery
- **HTTP endpoint** (port 8081) - Health checks and Prometheus metrics

## Quick Start

### Docker (Recommended)

```bash
# Build and run
docker build -t vauchi-relay .
docker run -d \
  --name vauchi-relay \
  -p 8080:8080 \
  -p 8081:8081 \
  -v relay-data:/data \
  vauchi-relay

# Check health
curl http://localhost:8081/health
```

### Docker Compose

```bash
docker-compose up -d
```

### Docker Compose with OHTTP (Recommended for Privacy)

The OHTTP deployment uses three containers: Caddy for TLS termination,
an OHTTP relay that strips client IPs, and a Vauchi relay on an internal-only
Docker network.

```
Client → Caddy (443, auto-TLS) → OHTTP Relay (8082) → Vauchi Relay (8080, internal only)
```

```bash
# Set your domain (required for Let's Encrypt)
export RELAY_DOMAIN=relay.example.com

docker compose -f deploy/docker-compose.ohttp.yml up -d

# Verify health
curl -s https://$RELAY_DOMAIN/health
```

Caddy auto-manages TLS certificates via Let's Encrypt. Client IPs are redacted
from Caddy's logs. The OHTTP relay forwards only opaque encrypted blobs — it
never sees request content or mailbox tokens.

**Network isolation:**

| Service | Networks | Internet access | External ports |
|---------|----------|-----------------|----------------|
| `caddy` | `external` | Yes | 80, 443 |
| `ohttp-relay` | `external`, `internal` | Yes | None |
| `vauchi-relay` | `internal` | No | None |

See `deploy/docker-compose.ohttp.yml` and `deploy/Caddyfile.ohttp` for full
configuration.

## Production Deployment

### 1. TLS Termination

The relay doesn't handle TLS directly. Use a reverse proxy:

**nginx:**
```bash
# Copy and customize the config
sudo cp deploy/nginx/vauchi-relay.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/vauchi-relay.conf /etc/nginx/sites-enabled/

# Get certificates with certbot
sudo certbot --nginx -d relay.vauchi.example.com

# Reload nginx
sudo systemctl reload nginx
```

**Caddy:**
```bash
# Copy Caddyfile
sudo cp deploy/caddy/Caddyfile /etc/caddy/

# Caddy handles TLS automatically
sudo systemctl restart caddy
```

### 2. Systemd Service

For bare-metal Linux deployments:

```bash
# Run the install script
sudo ./deploy/install.sh

# Or manually:
sudo cp target/release/vauchi-relay /usr/local/bin/
sudo cp deploy/systemd/vauchi-relay.service /etc/systemd/system/
sudo useradd -r -s /bin/false vauchi
sudo mkdir -p /var/lib/vauchi-relay
sudo chown vauchi:vauchi /var/lib/vauchi-relay
sudo systemctl daemon-reload
sudo systemctl enable --now vauchi-relay
```

### 3. Kubernetes

```bash
# Add Helm repo (if published)
# helm repo add vauchi https://charts.vauchi.example.com

# Or install from local chart
helm install vauchi-relay deploy/helm/vauchi-relay \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=relay.vauchi.example.com \
  --set ingress.tls[0].secretName=vauchi-relay-tls \
  --set ingress.tls[0].hosts[0]=relay.vauchi.example.com
```

## Static Binary (musl)

Phase 2 of the distroless migration produces a fully static binary linked against musl libc,
shrinking the image from ~32.7 MB (`distroless/cc`) to ~11.2 MB (`distroless/static`).

### Binary characteristics

- **Size**: 9.1 MiB on disk
- **CVEs**: 0 (no shared libraries to scan)
- **Linking**: static-PIE (`-static -pie`)
- **Shared library dependencies**: none (`ldd` reports "not a dynamic executable")

### Build requirements (build-time only)

The following packages are needed in the build environment and are **not** present in the
runtime image:

```
musl-tools   # provides musl-gcc wrapper and CRT objects
cmake        # required by aws-lc-rs
clang        # alternative C compiler used by aws-lc-rs
perl         # required by aws-lc-rs build scripts
```

Add the musl target once:

```bash
rustup target add x86_64-unknown-linux-musl
```

### mimalloc allocator

musl's default `malloc` uses a global lock. Under concurrent load this causes a 51–700%
throughput regression compared to glibc. The relay links [mimalloc](https://github.com/microsoft/mimalloc)
as a replacement allocator, reducing the delta to ~13%.

The allocator is enabled via the `mimalloc` Cargo feature and requires no runtime configuration.

### Build command

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

No `CC` or `LINKER` environment variable overrides are needed. Rust uses the bundled musl CRT
objects automatically.

### Runtime image

```
gcr.io/distroless/static-debian12
```

This image contains only four Debian packages: `base-files`, `media-types`, `netbase`, `tzdata`.
There is no shell, no package manager, and no C runtime — the musl binary is fully self-contained.

### Known issues

**Arch Linux musl-gcc SIGSEGV**

On Arch Linux, `musl-gcc` has a spec-file bug that misconfigures `scrt1.o`, causing a SIGSEGV at
startup. Fix: do not set `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc`. Let Rust
resolve the linker automatically — it will use the bundled musl CRT, which is correct.

**Intermittent test failure: `test_relay_id_file_persistence`**

This test fails intermittently when run in parallel due to environment variable pollution.
The failure is pre-existing and also reproduces on glibc builds. It is not a musl regression.
Workaround: run the test serially (`cargo nextest run --test-threads=1`) or skip it in CI
parallel runs.

---

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_LISTEN_ADDR` | `0.0.0.0:8080` | WebSocket listen address |
| `RELAY_MAX_CONNECTIONS` | `1000` | Max concurrent connections |
| `RELAY_MAX_MESSAGE_SIZE` | `1048576` | Max message size (1MB) |
| `RELAY_BLOB_TTL_DAYS` | `90` | Blob expiration in days |
| `RELAY_RATE_LIMIT_PER_MIN` | `60` | Max messages per client per minute |
| `RELAY_CLEANUP_INTERVAL` | `3600` | Cleanup interval in seconds |
| `RELAY_STORAGE_BACKEND` | `sqlite` | `memory` or `sqlite` |
| `RELAY_DATA_DIR` | `/data` | Data directory for SQLite |

## Monitoring

### Health Endpoints

- `GET /health` - Liveness check (always 200 if running)
- `GET /ready` - Readiness check (200 if storage accessible)

### Prometheus Metrics

Available at `GET /metrics` on port 8081:

```
# Connection metrics
relay_connections_total
relay_connections_active
relay_connection_errors_total

# Message metrics
relay_messages_received_total
relay_messages_sent_total
relay_messages_rejected_total
relay_message_duration_seconds

# Storage metrics
relay_blobs_stored
relay_blobs_created_total
relay_blobs_delivered_total
relay_blobs_expired_total

# Recovery metrics
relay_recovery_proofs_active
relay_recovery_vouchers_total

# Rate limiting
relay_rate_limited_total

# Runtime
relay_panics_total

# Federation (when enabled)
relay_federation_peers_connected
relay_federation_peer_connections_total
relay_federation_peer_connection_errors_total
relay_federation_offloads_sent_total
relay_federation_offloads_received_total
relay_federation_offloads_rejected_total
relay_federation_hints_active
relay_federation_hints_stored_total
relay_federation_hints_expired_total
relay_federation_drain_notices_total
relay_federation_rate_limited_total
```

### Grafana Dashboard

Import `deploy/grafana/relay-dashboard.json` into Grafana. It includes panels for connections, messages, storage, and federation.

For operational runbooks (incident response, maintenance, troubleshooting), see `RUNBOOKS.md`.

## Security

### Network

- Deploy behind a reverse proxy for TLS
- Use firewall to restrict direct access to ports 8080/8081
- Only expose port 443 (HTTPS/WSS) publicly

### Container

The Docker image runs as non-root user `vauchi` (UID 1000).

### Systemd

The systemd service includes security hardening:
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `PrivateTmp=yes`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`

## Scaling

### Horizontal Scaling

For high availability:

1. Deploy multiple relay instances
2. Use a load balancer with WebSocket support (sticky sessions recommended)
3. Each instance uses its own SQLite database

Note: Blob distribution between relays is not implemented yet. Each client should connect to the same relay for message delivery.

### Vertical Scaling

Tune these for your workload:
- `RELAY_MAX_CONNECTIONS` - Increase for more clients
- `RELAY_RATE_LIMIT_PER_MIN` - Adjust for expected message rate
- Allocate more memory for in-memory storage mode

## Troubleshooting

### Check logs

```bash
# Docker
docker logs vauchi-relay

# Systemd
journalctl -u vauchi-relay -f

# Kubernetes
kubectl logs -l app=vauchi-relay -f
```

### Common issues

**"Address already in use"**
- Another process using port 8080/8081
- Check with `lsof -i :8080`

**"Permission denied" for data directory**
- Ensure the vauchi user owns the data directory
- `chown -R vauchi:vauchi /var/lib/vauchi-relay`

**High memory usage**
- Switch from `memory` to `sqlite` storage backend
- Reduce `RELAY_BLOB_TTL_DAYS`
- Check for connection leaks

## Ops Validation Checklist (musl static binary)

Complete these steps before promoting the musl image to production:

- [ ] CI Docker build with musl target passes
- [ ] Container scanning shows 0 CVEs
- [ ] k6 performance test: p95 latency comparable to glibc baseline
- [ ] k6 performance test: throughput comparable to glibc baseline
- [ ] Staging deploy via Kamal succeeds
- [ ] Federation peer DNS resolution works on musl
- [ ] 24h production soak test: RSS stable, fd count stable
- [ ] Production deploy
