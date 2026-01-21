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

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_LISTEN_ADDR` | `0.0.0.0:8080` | WebSocket listen address |
| `RELAY_MAX_CONNECTIONS` | `1000` | Max concurrent connections |
| `RELAY_MAX_MESSAGE_SIZE` | `1048576` | Max message size (1MB) |
| `RELAY_BLOB_TTL_DAYS` | `90` | Blob expiration in days |
| `RELAY_RATE_LIMIT_PER_MIN` | `60` | Max messages per client per minute |
| `RELAY_CLEANUP_INTERVAL_SECS` | `3600` | Cleanup interval in seconds |
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
```

### Grafana Dashboard

Example Prometheus queries for a dashboard:

```promql
# Connection rate
rate(relay_connections_total[5m])

# Active connections
relay_connections_active

# Message throughput
rate(relay_messages_received_total[5m])

# Error rate
rate(relay_connection_errors_total[5m]) / rate(relay_connections_total[5m])

# Storage utilization
relay_blobs_stored

# Rate limiting events
rate(relay_rate_limited_total[5m])
```

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
