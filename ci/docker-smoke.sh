#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: AGPL-3.0-or-later

# A started relay serves a client: one blob sent to a mailbox comes back on
# fetch. CI points it at the built image; locally, at a running binary.
# Usage: ci/docker-smoke.sh <relay HTTP API base URL>
# @scenario: relay_network :: Deploy relay node with Docker

set -eu

base=${1:?usage: docker-smoke.sh <relay HTTP API base URL>}

for _ in $(seq 1 30); do
    curl -sf "$base/health" >/dev/null 2>&1 && break
    sleep 1
done
curl -sf "$base/health" >/dev/null || {
    echo "Relay did not start" >&2
    exit 1
}

mailbox=$(head -c 64 /dev/zero | tr '\0' c)
ciphertext=$(printf 'docker-smoke' | base64)
post() {
    status=$(curl -s -o "$response" -w "%{http_code}" -H "Content-Type: application/json" \
        "$base/$1" -d "$2") || status=000
    [ "$status" = 200 ] || {
        echo "POST $1 -> HTTP $status: $(cat "$response")" >&2
        exit 1
    }
}

response=$(mktemp)
trap 'rm -f "$response"' EXIT
post v2/send "{\"version\":2,\"recipient_id\":\"$mailbox\",\"ciphertext\":\"$ciphertext\"}"
post v2/fetch "{\"version\":2,\"mailbox_tokens\":[\"$mailbox\"]}"
fetched=$(jq -r '.blobs[0].ciphertext' "$response")

[ "$fetched" = "$ciphertext" ] || {
    echo "Relay did not return the sent blob (got: $fetched)" >&2
    exit 1
}
echo "Relay started and returned the sent blob"
