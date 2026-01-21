#!/usr/bin/env bash
# Test script for vauchi-relay WebSocket endpoint
# Usage: ./test-relay.sh [hostname]
# Example: ./test-relay.sh relay.vauchi.app

set -uo pipefail

HOST="${1:-relay.vauchi.app}"
PASS=0
FAIL=0

check() {
    local name="$1" result="$2" expected="$3"
    if [[ "$result" == *"$expected"* ]]; then
        echo "✓ $name"
        PASS=$((PASS + 1))
    else
        echo "✗ $name"
        echo "  Expected: $expected"
        echo "  Got: $result"
        FAIL=$((FAIL + 1))
    fi
}

echo "Testing relay at: $HOST"
echo "─────────────────────────────"

# 1. Health endpoint
health=$(curl -s --connect-timeout 5 "https://$HOST/health" 2>&1 || echo "CURL_FAILED")
check "Health endpoint" "$health" '"status":"healthy"'
check "Health includes blob_count" "$health" '"blob_count":'

# 1b. Ready endpoint
ready=$(curl -s --connect-timeout 5 "https://$HOST/ready" 2>&1 || echo "CURL_FAILED")
check "Ready endpoint" "$ready" '"status":"healthy"'

# 2. Check if we're hitting the relay, not the landing page
root=$(curl -s -i --connect-timeout 5 "https://$HOST/" 2>&1 || echo "CURL_FAILED")
if echo "$root" | grep -qi "Content-Type: text/html"; then
    echo "✗ Routing error: Received HTML instead of JSON"
    echo "  This usually means kamal-proxy is routing to the landing page instead of the relay."
    FAIL=$((FAIL + 1))
else
    # Accept both HTTP/1.1 and HTTP/2 responses
    if echo "$root" | grep -qE "HTTP/(1.1|2) 200"; then
        echo "✓ Relay identity check (HTTP 200)"
        PASS=$((PASS + 1))
    else
        echo "✗ Relay identity check (expected HTTP 200)"
        echo "  Got: $(echo "$root" | head -n 1)"
        FAIL=$((FAIL + 1))
    fi
    check "Relay identity check (JSON content)" "$root" '"error":"This is a WebSocket relay endpoint"'
fi

# 3. HTTP redirects to HTTPS
# We expect a 301 from the proxy if accessing via HTTP
redirect=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$HOST/" 2>&1 || echo "000")
check "HTTP→HTTPS redirect" "$redirect" "301"

# 4. WebSocket Upgrade (The core test)
echo "Testing WebSocket upgrade..."
# Force HTTP/1.1 since WebSocket upgrade (101) is an HTTP/1.1 mechanism
# Use --max-time to prevent hanging if upgrade succeeds (curl waits for data)
ws_headers=$(curl -s -i --http1.1 --connect-timeout 5 --max-time 3 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://$HOST" 2>&1 || echo "CURL_FAILED")

if echo "$ws_headers" | grep -qE "HTTP/1\.[01] 101"; then
    echo "✓ WebSocket upgrade (101 Switching Protocols)"
    PASS=$((PASS + 1))
elif echo "$ws_headers" | grep -qE "HTTP/1\.[01] 400"; then
    echo "✗ WebSocket upgrade failed (400 Bad Request)"
    echo "  The relay is reachable but rejected the upgrade."
    echo "  Check if 'Upgrade: websocket' and 'Connection: Upgrade' headers are being stripped by proxy."
    FAIL=$((FAIL + 1))
elif echo "$ws_headers" | grep -qE "HTTP/1\.[01] 404"; then
    echo "✗ WebSocket upgrade failed (404 Not Found)"
    echo "  The relay is reachable but rejected the path."
    FAIL=$((FAIL + 1))
else
    echo "✗ WebSocket upgrade failed"
    echo "  Expected HTTP 101, but got something else."
    echo "  Response snippet:"
    echo "$ws_headers" | head -n 5
    FAIL=$((FAIL + 1))
fi

# 5. Check that root DOES NOT upgrade (REMOVED: root SHOULD upgrade)
# echo "Checking that root path does NOT upgrade..."
# ... (removed)

# 6. Full WebSocket connection (if websocat is available)
if command -v websocat &>/dev/null; then
    ws_conn=$(timeout 3 websocat -v "wss://$HOST" </dev/null 2>&1 || true)
    if [[ "$ws_conn" == *"Connected to ws"* ]]; then
        echo "✓ Full WebSocket handshake"
        PASS=$((PASS + 1))
    else
        echo "✗ Full WebSocket handshake failed"
        FAIL=$((FAIL + 1))
    fi
fi

echo "─────────────────────────────"
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
