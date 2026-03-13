<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vauchi Relay Operational Runbooks

Step-by-step procedures for relay operators. All commands assume systemd deployment; adapt paths for Docker/Kubernetes.

---

## 1. Deployment

### 1.1 Fresh Install

```bash
# Build release binary
cargo build --release -p vauchi-relay

# Install
sudo ./deploy/install.sh

# Verify
curl -s http://localhost:8081/health
# Expected: {"status":"ok"}
```

### 1.2 Rolling Upgrade

```bash
# Build new binary
cargo build --release -p vauchi-relay

# Stop, replace, start (clients reconnect automatically)
sudo systemctl stop vauchi-relay
sudo cp target/release/vauchi-relay /usr/local/bin/vauchi-relay
sudo systemctl start vauchi-relay

# Verify
curl -s http://localhost:8081/health
journalctl -u vauchi-relay --since "1 minute ago" --no-pager
```

### 1.3 Rollback

```bash
# Keep previous binary before upgrade
sudo cp /usr/local/bin/vauchi-relay /usr/local/bin/vauchi-relay.bak

# Rollback
sudo systemctl stop vauchi-relay
sudo cp /usr/local/bin/vauchi-relay.bak /usr/local/bin/vauchi-relay
sudo systemctl start vauchi-relay
```

### 1.4 TLS Certificate Rotation

```bash
# nginx + certbot
sudo certbot renew
sudo systemctl reload nginx

# Caddy (automatic, but force if needed)
sudo systemctl restart caddy

# Verify
openssl s_client -connect relay.example.com:443 -servername relay.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates
```

### 1.5 Federation mTLS Certificate Rotation

```bash
# Generate new certificates (see federation docs)
# Place in configured paths:
#   RELAY_MTLS_CERT=/etc/vauchi-relay/federation.crt
#   RELAY_MTLS_KEY=/etc/vauchi-relay/federation.key
#   RELAY_MTLS_CA=/etc/vauchi-relay/federation-ca.crt

# Restart to load new certs
sudo systemctl restart vauchi-relay

# Verify peer connections re-establish
journalctl -u vauchi-relay --since "1 minute ago" | grep "fed-conn"
```

---

## 2. Incident Response

### 2.1 High Memory Usage

**Symptoms**: OOM kills, `relay_blobs_stored` growing, swap usage.

```bash
# Check current blob count
curl -s http://localhost:8081/metrics | grep relay_blobs_stored

# Check data directory size
du -sh /var/lib/vauchi-relay/

# Force cleanup (reduce TTL temporarily)
sudo systemctl stop vauchi-relay
# Edit service to add: Environment=RELAY_BLOB_TTL_SECS=86400
sudo systemctl daemon-reload
sudo systemctl start vauchi-relay

# Wait for cleanup cycle, then restore normal TTL
```

### 2.2 Connection Storm

**Symptoms**: `relay_connections_active` spike, `relay_rate_limited_total` increasing, high CPU.

```bash
# Check current connections
curl -s http://localhost:8081/metrics | grep relay_connections_active

# Temporary rate limit reduction
# Edit service: Environment=RELAY_RATE_LIMIT=10
sudo systemctl daemon-reload
sudo systemctl restart vauchi-relay

# Monitor recovery
watch -n5 'curl -s http://localhost:8081/metrics | grep -E "connections_active|rate_limited"'

# Restore normal rate limit after storm passes
```

### 2.3 Federation Peer Disconnected

**Symptoms**: `relay_federation_peers_connected` drops, `relay_federation_peer_connection_errors_total` increasing.

```bash
# Check peer status
curl -s http://localhost:8081/metrics | grep federation_peer

# Check logs for specific error
journalctl -u vauchi-relay --since "10 minutes ago" | grep "fed-conn"

# Common causes:
# - Peer relay down: wait for automatic reconnect (exponential backoff)
# - mTLS cert expired: rotate certificates (see 1.5)
# - SSRF validation: check peer URL is not private/loopback
# - Version mismatch: ensure both relays run compatible versions
```

### 2.4 High Offload Rejection Rate

**Symptoms**: `relay_federation_offloads_rejected_total` increasing faster than `relay_federation_offloads_received_total`.

```bash
# Check rejection rate
curl -s http://localhost:8081/metrics | grep federation_offloads

# Check logs for rejection reasons
journalctl -u vauchi-relay --since "10 minutes ago" | grep -E "hop_count|integrity|at capacity"

# If "at capacity": increase storage or reduce TTL
# If "integrity": investigate network corruption or malicious peer
# If "hop_count": expected — prevents re-offloading loops
```

### 2.5 Panic Detected

**Symptoms**: `relay_panics_total` incremented, structured error in logs.

```bash
# Check panic count
curl -s http://localhost:8081/metrics | grep relay_panics_total

# Find the panic in logs (JSON structured)
journalctl -u vauchi-relay --since "1 hour ago" | grep '"panic"'

# relay uses panic=abort in release mode, so a panic kills the process
# systemd auto-restarts after 5s (RestartSec=5)
# Check restart count:
systemctl show vauchi-relay --property=NRestarts
```

---

## 3. Operations

### 3.1 Backup SQLite Database

```bash
# Online backup using SQLite .backup
sudo -u vauchi sqlite3 /var/lib/vauchi-relay/relay.db ".backup /var/lib/vauchi-relay/backup-$(date +%Y%m%d).db"

# Verify backup
sqlite3 /var/lib/vauchi-relay/backup-*.db "SELECT count(*) FROM blobs;"
```

### 3.2 Database Vacuum

```bash
# Stop relay for offline vacuum (reduces file size)
sudo systemctl stop vauchi-relay
sudo -u vauchi sqlite3 /var/lib/vauchi-relay/relay.db "VACUUM;"
sudo systemctl start vauchi-relay
```

### 3.3 Check Disk Usage

```bash
# Storage breakdown
du -sh /var/lib/vauchi-relay/*

# SQLite table sizes
sudo -u vauchi sqlite3 /var/lib/vauchi-relay/relay.db "
  SELECT 'blobs', count(*), sum(length(data)) FROM blobs;
  SELECT 'recovery_proofs', count(*), sum(length(proof_data)) FROM recovery_proofs;
  SELECT 'device_sync', count(*), sum(length(encrypted_payload)) FROM device_sync_messages;
  SELECT 'forwarding_hints', count(*), 0 FROM forwarding_hints;
"
```

### 3.4 Drain Before Maintenance

```bash
# Step 1: Stop accepting new connections (remove from load balancer)
# Step 2: Wait for existing connections to close naturally
# Step 3: Check no active connections remain
curl -s http://localhost:8081/metrics | grep relay_connections_active
# Expected: relay_connections_active 0

# Step 4: Stop service
sudo systemctl stop vauchi-relay
```

### 3.5 Log Level Adjustment

```bash
# Increase verbosity for debugging
sudo systemctl set-environment RUST_LOG=vauchi_relay=debug
sudo systemctl restart vauchi-relay

# Restore normal level
sudo systemctl set-environment RUST_LOG=vauchi_relay=info
sudo systemctl restart vauchi-relay

# Enable JSON logging for structured analysis
sudo systemctl set-environment RELAY_LOG_FORMAT=json
sudo systemctl restart vauchi-relay
```

### 3.6 Prometheus Scrape Verification

```bash
# Check metrics endpoint is reachable
curl -s http://localhost:8081/metrics | head -20

# Verify metric names match Grafana dashboard expectations
curl -s http://localhost:8081/metrics | grep -c "^relay_"

# Import dashboard: deploy/grafana/relay-dashboard.json
```

---

## 4. Reference

### 4.1 Key Metrics and Thresholds

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| `relay_connections_active` | < 500 | > 800 | > 950 (near limit) |
| `relay_panics_total` | 0 | any | rapid increase |
| `relay_blobs_stored` | stable | growing > 10k | > 100k |
| `relay_rate_limited_total` rate | < 1/s | > 10/s | > 100/s |
| `relay_federation_peers_connected` | = configured count | < configured | 0 |
| `relay_message_duration_seconds` p95 | < 10ms | > 50ms | > 200ms |

### 4.2 Log Formats

**Default (human-readable)**:
```
2026-03-13T10:00:00Z  INFO vauchi_relay: Listening on 0.0.0.0:8080
2026-03-13T10:00:01Z  WARN vauchi_relay::handler: [abc12345] Rate limited
```

**JSON (set `RELAY_LOG_FORMAT=json`)**:
```json
{"timestamp":"2026-03-13T10:00:00Z","level":"INFO","target":"vauchi_relay","message":"Listening on 0.0.0.0:8080"}
```

### 4.3 Port Map

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | WebSocket | Client connections |
| 8081 | HTTP | Health + metrics |
| 8082* | WebSocket+mTLS | Federation (when configured) |

*mTLS port defaults to listen_addr + 1, configurable via `RELAY_MTLS_ADDR`.

### 4.4 Environment Variables (Full)

See `DEPLOYMENT.md` for the core set. Additional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_LOG_FORMAT` | `text` | `text` or `json` |
| `RELAY_FEDERATION_ENABLED` | `false` | Enable federation |
| `RELAY_FEDERATION_RELAY_ID` | | Unique relay identifier |
| `RELAY_FEDERATION_PEERS` | | Comma-separated peer URLs |
| `RELAY_MTLS_CERT` | | Federation mTLS cert path |
| `RELAY_MTLS_KEY` | | Federation mTLS key path |
| `RELAY_MTLS_CA` | | Federation CA cert path |
| `RELAY_MAX_STORAGE_BYTES` | `10737418240` | Max storage (10GB) |

### 4.5 File Descriptor Budget

The systemd service sets `LimitNOFILE=65536`. Budget:

| Consumer | FDs |
|----------|-----|
| WebSocket connections | 1 per client (max 1000) |
| SQLite databases | ~10 (blobs, recovery, sync, hints) |
| Federation peers | 1 per peer |
| TCP listener | 1 per port (2-3) |
| Logging, misc | ~20 |
| **Total max** | **~1040** |

The 65536 limit provides ample headroom.
