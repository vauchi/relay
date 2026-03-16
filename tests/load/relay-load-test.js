// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

// k6 Load Test for Vauchi Relay (PI-10)
//
// Tests WebSocket connection throughput and latency under load.
// Requires relay running with RELAY_REQUIRE_NOISE_ENCRYPTION=false
// for plaintext v1 protocol (Noise NK handshake is not practical in k6).
//
// Usage:
//   k6 run relay/tests/load/relay-load-test.js
//   k6 run --env RELAY_URL=ws://staging:8080 relay/tests/load/relay-load-test.js

import ws from "k6/ws";
import { check, sleep } from "k6";
import { Counter, Trend } from "k6/metrics";

// ============================================================
// Configuration
// ============================================================

const RELAY_URL = __ENV.RELAY_URL || "ws://127.0.0.1:8080";
const HEALTH_URL = RELAY_URL.replace("ws://", "http://").replace("wss://", "https://") + "/health";

export const options = {
  stages: [
    { duration: "10s", target: 10 },   // Ramp up to 10 VUs
    { duration: "40s", target: 10 },   // Sustain 10 VUs
    { duration: "10s", target: 0 },    // Ramp down
  ],
  thresholds: {
    ws_connecting: ["p(95)<500"],       // p95 connection < 500ms
    messages_sent: ["count>50"],        // Total messages sent across all VUs
    handshake_time: ["p(95)<300"],      // p95 handshake < 300ms
    message_ack_time: ["p(95)<500"],    // p95 message round-trip < 500ms
  },
};

// ============================================================
// Custom metrics
// ============================================================

const messagesSent = new Counter("messages_sent");
const handshakeTime = new Trend("handshake_time", true);
const messageAckTime = new Trend("message_ack_time", true);
const connectionErrors = new Counter("connection_errors");

// ============================================================
// Helpers
// ============================================================

// Generate a deterministic 64-char hex string (simulates Ed25519 public key)
function generateClientId(vuId) {
  const hex = "0123456789abcdef";
  let id = "";
  const seed = `vu-${vuId}-${Date.now()}`;
  for (let i = 0; i < 64; i++) {
    id += hex[Math.abs(seed.charCodeAt(i % seed.length) + i) % 16];
  }
  return id;
}

// Build a length-prefixed binary frame from a JSON object
function encodeFrame(obj) {
  const json = JSON.stringify(obj);
  const jsonBytes = new Uint8Array(json.length);
  for (let i = 0; i < json.length; i++) {
    jsonBytes[i] = json.charCodeAt(i);
  }

  const frame = new ArrayBuffer(4 + jsonBytes.length);
  const view = new DataView(frame);
  view.setUint32(0, jsonBytes.length, false); // big-endian

  const arr = new Uint8Array(frame);
  arr.set(jsonBytes, 4);

  return frame;
}

function makeEnvelope(payload) {
  return {
    version: 1,
    message_id: `msg-${__VU}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Math.floor(Date.now() / 1000),
    payload: payload,
  };
}

// ============================================================
// Main scenario
// ============================================================

export default function () {
  const clientId = generateClientId(__VU);
  // Use a different recipient (next VU's ID pattern) to avoid self-delivery loops
  const recipientId = generateClientId(__VU + 1000);

  const handshakeStart = Date.now();
  // Track the most recent send timestamp for ack latency measurement.
  // Each server response is attributed to the last send, giving a conservative
  // (upper-bound) RTT estimate without requiring request-response correlation.
  let lastSendTime = handshakeStart;

  const res = ws.connect(RELAY_URL, null, function (socket) {
    let handshakeAcked = false;

    socket.on("open", function () {
      // Send Handshake (mandatory first message)
      const handshake = makeEnvelope({
        type: "Handshake",
        client_id: clientId,
      });
      lastSendTime = Date.now();
      socket.sendBinary(encodeFrame(handshake));
    });

    socket.on("binaryMessage", function () {
      const now = Date.now();
      if (!handshakeAcked) {
        handshakeAcked = true;
        handshakeTime.add(now - handshakeStart);
      }

      // Track per-message ACK latency (delta from last send, not connection start)
      messageAckTime.add(now - lastSendTime);
    });

    socket.on("error", function () {
      connectionErrors.add(1);
    });

    function sendUpdate(ciphertextLen) {
      const update = makeEnvelope({
        type: "EncryptedUpdate",
        recipient_id: recipientId,
        ciphertext: Array.from({ length: ciphertextLen }, (_, j) => j % 256),
      });
      lastSendTime = Date.now();
      socket.sendBinary(encodeFrame(update));
      messagesSent.add(1);
    }

    // After connection, send EncryptedUpdate messages
    socket.setTimeout(function () {
      if (!handshakeAcked) {
        return;
      }

      // Send a burst of messages
      for (let i = 0; i < 5; i++) {
        sendUpdate(256);
      }
    }, 1000); // Wait 1s for handshake to complete

    // Send periodic messages during the connection
    for (let t = 2; t <= 5; t++) {
      socket.setTimeout(function () {
        sendUpdate(128);
      }, t * 1000);
    }

    // Close connection after 6 seconds
    socket.setTimeout(function () {
      socket.close();
    }, 6000);
  });

  check(res, {
    "WebSocket connected": (r) => r && r.status === 101,
  });

  sleep(1);
}
