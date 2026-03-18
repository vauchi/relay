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
#   RELAY_FEDERATION_TLS_CERT=/etc/vauchi-relay/federation.crt
#   RELAY_FEDERATION_TLS_KEY=/etc/vauchi-relay/federation.key
#   RELAY_FEDERATION_TLS_CA=/etc/vauchi-relay/federation-ca.crt

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

## 4. Privacy & Security Operations

### 4.1 Operator Observability Matrix

Operators have access to **metadata and metrics only**. Message content is end-to-end encrypted and **never accessible** to relay operators.

| Category | Operators CAN see | Operators CANNOT see |
|----------|-------------------|----------------------|
| **Traffic** | Connection count, connection rate, WebSocket close codes | Which clients are communicating with each other |
| **Blobs** | Blob count (`relay_blobs_stored`), blob sizes in aggregate, TTL expiry count | Blob contents (encrypted), what data the blob contains |
| **Routing** | `routing_id` (opaque random identifier), blob retrieval timing | Sender identity, receiver identity, contact card data |
| **Federation** | Peer relay URL, peer connection status, offload counts, hop counts | Which users are federated, cross-relay message routing graph |
| **Performance** | `relay_message_duration_seconds` percentiles, rate limit counters, error rates | Request payload content, client IP (not logged by default) |
| **Storage** | Total storage bytes, database row counts per table | Encrypted payload contents in any table |
| **Incidents** | Panic count, restart count, OOM events | Any user-identifying information during incident |

**Key invariant**: The `routing_id` is a random opaque token generated by the client. It does not encode user identity, device identity, or contact card references in any recoverable form. Operators see routing IDs in logs but cannot map them to users.

### 4.2 Privacy-Safe Debugging Guidelines

**Principles:**

1. **Never log payload content.** The relay must never emit blob data, message content, or decrypted fields at any log level, including `TRACE`. If debugging a serialization issue, log only byte lengths and structural metadata.

2. **Use `routing_id`, not user identity.** When tracing a request through logs, reference the `routing_id` only. Do not attempt to correlate routing IDs across sessions — each retrieval uses a fresh routing ID by design.

3. **Scrub logs before sharing.** Before sharing logs with third parties (support, upstream bug reports), strip all routing IDs with a placeholder:
   ```bash
   # Replace routing_id values with [REDACTED]
   journalctl -u vauchi-relay --since "1 hour ago" | \
     sed -E 's/routing_id=[a-f0-9]+/routing_id=[REDACTED]/g'
   ```

4. **Use synthetic data for reproduction.** Never reproduce production issues using real user data. Generate synthetic blobs of the same size class:
   ```bash
   # Generate a 512-byte synthetic blob for testing
   head -c 512 /dev/urandom | base64 > /tmp/synthetic-blob.bin
   ```

5. **Metrics-only incident response.** For delivery failures and performance issues, diagnose exclusively through Prometheus metrics and aggregate log patterns. See section 5.4 for the delivery failure workflow.

6. **No IP address logging.** The relay does not log client IP addresses by default. If enabling IP logging for abuse investigation, treat IP addresses as PII: store separately, apply retention limits, and delete after the investigation.

7. **Federation peer URLs are semi-public.** Peer relay URLs appear in config and metrics. Do not include authentication tokens or credentials in peer URLs.

---

## 5. Extended Incident & Operational Procedures

### 5.1 Emergency Hotfix Procedure

Use when a critical bug (security vulnerability, data loss, relay unavailability) requires immediate deployment without waiting for the full CI pipeline.

**Criteria for emergency hotfix:**
- CVSS ≥ 7.0 vulnerability in relay or a dependency
- Relay crashing in production (multiple restarts within 10 minutes)
- Data integrity issue affecting blob storage

**Procedure:**

```bash
# 1. Create a hotfix branch from the current deployed tag
git -C relay checkout -b hotfix/describe-issue $(git -C relay describe --tags --abbrev=0)

# 2. Apply the fix
# ... make the minimal code change ...

# 3. Run abbreviated checks: skip mutation tests, keep lint + unit tests
cargo fmt --check -p vauchi-relay
cargo clippy -p vauchi-relay -- -D warnings
cargo test -p vauchi-relay

# 4. Commit and push for review (MR required even for hotfixes)
git -C relay add -p
git -C relay commit -m "fix: <description>"
# Open MR with 'hotfix' label — request expedited review

# 5. After MR approval, build and deploy immediately
cargo build --release -p vauchi-relay
sudo systemctl stop vauchi-relay
sudo cp /usr/local/bin/vauchi-relay /usr/local/bin/vauchi-relay.bak  # always keep backup
sudo cp target/release/vauchi-relay /usr/local/bin/vauchi-relay
sudo systemctl start vauchi-relay

# 6. Verify recovery
curl -s http://localhost:8081/health
journalctl -u vauchi-relay --since "2 minutes ago" --no-pager | tail -20
```

**What is skipped in an emergency hotfix:**
- Mutation testing (`cargo mutants`) — run post-incident
- Full integration test suite — run post-incident
- `just drift` analysis — run post-incident

**What is NOT skipped:**
- `cargo fmt --check` and `cargo clippy`
- `cargo test` (unit tests)
- MR review (at least one other reviewer)
- Post-incident: open a follow-up task to run the full suite

### 5.2 `cargo audit` Response Procedure

Run `cargo audit` regularly (automated in CI, or manually with `cargo audit`).

**Triage workflow:**

```bash
# Run audit
cargo audit -p vauchi-relay

# Check for ignored advisories
cat relay/audit.toml  # or .cargo/audit.toml
```

**Severity triage:**

| Advisory severity | Action | Timeline |
|-------------------|--------|----------|
| Critical (CVSS ≥ 9.0) | Patch immediately; use emergency hotfix if relay is affected | Same day |
| High (CVSS 7.0–8.9) | Patch in next planned release or within 72 hours if relay is affected | 72 hours |
| Medium (CVSS 4.0–6.9) | Patch within two weeks | 2 weeks |
| Low (CVSS < 4.0) | Schedule in next sprint; add `ignore` to `audit.toml` with expiry comment if justified | Next sprint |

**Patch strategy:**

```bash
# Update a specific dependency
cargo update -p <crate-name>

# If the vulnerable version is pinned by a dependency you don't control:
# 1. Check if a newer version of the parent crate resolves it
cargo update -p <parent-crate>

# 2. If not, add a Cargo.toml patch override with justification comment:
# [patch.crates-io]
# vulnerable-crate = { version = "x.y.z" }  # security: advisory RUSTSEC-YYYY-NNNN

# 3. Run full checks after updating
just check relay

# 4. If the crate is not used by relay code paths at all, add to audit.toml:
# [[ignore]]
# id = "RUSTSEC-YYYY-NNNN"
# reason = "not used in vauchi-relay execution paths; review by YYYY-MM-DD"
```

**After patching:**
- Open an MR with the advisory ID in the commit message: `chore: update <crate> — RUSTSEC-YYYY-NNNN`
- For Critical/High: notify the operator mailing list after deploy

### 5.3 Scaling Guidelines

#### Horizontal Scaling (Multiple Relays + Federation)

The relay is designed to scale horizontally via federation. Each relay instance is independent; clients are directed to a relay by the app.

```
Client A ─── Relay 1 ──┐
                        ├── Federation offload ──── Relay 2 ─── Client B
Client C ─── Relay 1 ──┘
```

**Steps to add a relay to a federation:**

```bash
# On the existing relay: generate federation credentials for the new peer
# (See federation docs for CA setup)

# On the new relay: set environment variables
RELAY_FEDERATION_ENABLED=true
RELAY_FEDERATION_RELAY_ID=relay-2.example.com
RELAY_FEDERATION_PEERS=https://relay-1.example.com:8082
RELAY_FEDERATION_TLS_CERT=/etc/vauchi-relay/federation.crt
RELAY_FEDERATION_TLS_KEY=/etc/vauchi-relay/federation.key
RELAY_FEDERATION_TLS_CA=/etc/vauchi-relay/federation-ca.crt

# On the existing relay: add the new peer
# Edit service environment to append relay-2 URL to RELAY_FEDERATION_PEERS
sudo systemctl daemon-reload
sudo systemctl restart vauchi-relay

# Verify both sides show the peer as connected
curl -s http://relay-1.example.com:8081/metrics | grep federation_peers_connected
curl -s http://relay-2.example.com:8081/metrics | grep federation_peers_connected
# Both should show: relay_federation_peers_connected 1
```

**Load distribution**: Clients choose their relay at the application layer. There is no built-in load balancer; federation handles cross-relay delivery. For even load, ensure clients are distributed across relays in app configuration or DNS round-robin.

#### Vertical Scaling (Resource Limits)

**File descriptors** — the most common bottleneck:

```bash
# Current limit
systemctl show vauchi-relay --property=LimitNOFILE

# Increase if approaching the 1000-connection limit
# Edit /etc/systemd/system/vauchi-relay.service:
#   LimitNOFILE=131072

sudo systemctl daemon-reload
sudo systemctl restart vauchi-relay

# System-wide fd limit (if needed)
# /etc/security/limits.conf:
#   vauchi  hard  nofile  131072
```

**Memory** — blob storage is the primary driver:

```bash
# Estimate memory from blob count
curl -s http://localhost:8081/metrics | grep relay_blobs_stored
# Rule of thumb: each blob ≈ 1–64KB; size controlled by client

# To reduce memory pressure, lower blob TTL
# Edit service: Environment=RELAY_BLOB_TTL_SECS=86400  (1 day instead of default)
sudo systemctl daemon-reload
sudo systemctl restart vauchi-relay
```

**Concurrent connections** — controlled by `RELAY_MAX_CONNECTIONS` (default 1000):

```bash
# Increase connection limit (ensure fd budget covers it, see section 6.5)
# Edit service: Environment=RELAY_MAX_CONNECTIONS=2000
# Also update LimitNOFILE to at least RELAY_MAX_CONNECTIONS + 200
sudo systemctl daemon-reload
sudo systemctl restart vauchi-relay
```

### 5.4 Delivery Failure Investigation

A "delivery failure" means a client cannot retrieve a blob it expects to be present. **All diagnosis is metrics and log pattern based — never inspect blob content.**

**Step 1: Confirm the failure is real**

```bash
# Check error rates on the metrics endpoint
curl -s http://localhost:8081/metrics | grep -E "relay_errors_total|relay_blobs_stored"

# Check recent 404s in logs (routing_id not found)
journalctl -u vauchi-relay --since "10 minutes ago" | grep -c '"status":404'
```

**Step 2: Rule out TTL expiry**

```bash
# Check blob count trend — a sudden drop indicates mass expiry
curl -s http://localhost:8081/metrics | grep relay_blobs_stored

# Check current TTL setting
systemctl show vauchi-relay --property=Environment | grep BLOB_TTL
# Default is typically 7 days; if client waited longer, blob is gone by design
```

**Step 3: Rule out storage full**

```bash
# Check storage usage
curl -s http://localhost:8081/metrics | grep relay_storage_bytes_used
# Compare against RELAY_MAX_STORAGE_BYTES (default 10GB)

du -sh /var/lib/vauchi-relay/
```

**Step 4: Rule out federation offload**

```bash
# If federation is enabled, the blob may have been stored on a peer relay
curl -s http://localhost:8081/metrics | grep relay_federation_offloads_sent_total
# If this count is non-zero, some blobs are on peer relays
# The client app handles peer relay lookup automatically — this is expected behaviour
```

**Step 5: Rule out relay restarts during storage**

```bash
# Check restart history — a crash during a write could lose an in-flight blob
systemctl show vauchi-relay --property=NRestarts
journalctl -u vauchi-relay --since "1 hour ago" | grep -E "start|stop|restart|panic"
```

**Step 6: Escalation**

If steps 1–5 do not identify the cause, collect:
- Metrics snapshot: `curl -s http://localhost:8081/metrics > /tmp/metrics-$(date +%s).txt`
- Log excerpt (scrubbed per section 4.2): `journalctl -u vauchi-relay --since "1 hour ago" | sed -E 's/routing_id=[a-f0-9]+/routing_id=[REDACTED]/g' > /tmp/logs-scrubbed.txt`
- Relay version: `/usr/local/bin/vauchi-relay --version`

Open a bug report with these artifacts. **Do not include unscrubbed logs.**

---

## 6. Reference

### 6.1 Key Metrics and Thresholds

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| `relay_connections_active` | < 500 | > 800 | > 950 (near limit) |
| `relay_panics_total` | 0 | any | rapid increase |
| `relay_blobs_stored` | stable | growing > 10k | > 100k |
| `relay_rate_limited_total` rate | < 1/s | > 10/s | > 100/s |
| `relay_federation_peers_connected` | = configured count | < configured | 0 |
| `relay_message_duration_seconds` p95 | < 10ms | > 50ms | > 200ms |

### 6.2 Log Formats

**Default (human-readable)**:
```
2026-03-13T10:00:00Z  INFO vauchi_relay: Listening on 0.0.0.0:8080
2026-03-13T10:00:01Z  WARN vauchi_relay::handler: [abc12345] Rate limited
```

**JSON (set `RELAY_LOG_FORMAT=json`)**:
```json
{"timestamp":"2026-03-13T10:00:00Z","level":"INFO","target":"vauchi_relay","message":"Listening on 0.0.0.0:8080"}
```

### 6.3 Port Map

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | WebSocket | Client connections |
| 8081 | HTTP | Health + metrics |
| 8082* | WebSocket+mTLS | Federation (when configured) |

*mTLS port defaults to listen_addr + 1, configurable via `RELAY_MTLS_ADDR`.

### 6.4 Environment Variables (Full)

See `DEPLOYMENT.md` for the core set. Additional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_LOG_FORMAT` | `text` | `text` or `json` |
| `RELAY_FEDERATION_ENABLED` | `false` | Enable federation |
| `RELAY_FEDERATION_RELAY_ID` | | Unique relay identifier |
| `RELAY_FEDERATION_PEERS` | | Comma-separated peer URLs |
| `RELAY_FEDERATION_TLS_CERT` | | Federation mTLS cert path |
| `RELAY_FEDERATION_TLS_KEY` | | Federation mTLS key path |
| `RELAY_FEDERATION_TLS_CA` | | Federation CA cert path |
| `RELAY_MAX_STORAGE_BYTES` | `10737418240` | Max storage (10GB) |

### 6.5 File Descriptor Budget

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
