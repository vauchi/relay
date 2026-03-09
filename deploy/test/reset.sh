#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# Reset test relay between CI runs (memory backend, just restart)
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[$(date -Iseconds)] Resetting test relay..."
docker compose -f "$COMPOSE_DIR/docker-compose.yml" restart relay
echo "[$(date -Iseconds)] Test relay reset complete."
