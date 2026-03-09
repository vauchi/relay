#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# Nightly wipe script for demo relay
# Add to crontab: 0 3 * * * /path/to/wipe-cron.sh

set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[$(date -Iseconds)] Starting demo relay nightly wipe..."
docker compose -f "$COMPOSE_DIR/docker-compose.yml" down
docker volume rm demo-data 2>/dev/null || true
docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d
echo "[$(date -Iseconds)] Demo relay wipe complete."
