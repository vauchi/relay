<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Vauchi Relay — SLIs and SLOs

## What Are SLIs and SLOs?

A **Service Level Indicator (SLI)** is a quantitative measurement of service behaviour — a ratio or value derived directly from metrics. An **Service Level Objective (SLO)** is the target value or range an SLI must meet over a measurement window.

SLOs set a shared expectation between operators and users. They also define **error budgets**: the amount of permitted failure before the SLO is breached. Spending error budget on planned maintenance is acceptable; losing it to bugs or incidents is not.

> **Privacy note**: The relay never inspects message content. All SLIs measure metadata only (rates, durations, counts). No user-identifiable data appears in any metric.

---

## SLI / SLO Definitions

### SLI-1 — Delivery Success Rate

**What it measures**: Fraction of received messages that were accepted (not rejected due to rate limits, size violations, or policy).

**PromQL**:
```promql
1 - (
  rate(relay_messages_rejected_total[5m])
  /
  rate(relay_messages_received_total[5m])
)
```

**SLO**: >= **99.9%** over a 30-day window

**Error budget (30d)**: 0.1% × 30 × 24 × 60 min = **43.2 minutes** of fully-degraded delivery per month

**Notes**:
- Returns `NaN` when `relay_messages_received_total` rate is zero (no traffic). Treat `NaN` as "not applicable" rather than a violation.
- Rejections include rate-limited clients (`relay_rate_limited_total`) and oversized messages. Legitimate spam rejection does not count against this SLO — consider splitting if needed.

---

### SLI-2 — Relay Availability

**What it measures**: Fraction of time the `/health` endpoint returns HTTP 200, measured by an external synthetic probe (Blackbox Exporter or equivalent).

**PromQL** (requires `probe_success` from Blackbox Exporter):
```promql
avg_over_time(probe_success{job="vauchi-relay-health"}[30d])
```

**SLO**: >= **99.5%** over a 30-day window

**Error budget (30d)**: 0.5% × 30 × 24 × 60 min = **216 minutes** (~3.6 hours) per month

**Notes**:
- Configure Blackbox Exporter to probe `http://<relay-host>:8081/health` every 30 seconds.
- Expected response: `{"status":"ok"}` with HTTP 200.
- Distinguish planned maintenance windows from unplanned outages in your SLO reporting.

---

### SLI-3 — P99 Message Latency

**What it measures**: 99th-percentile end-to-end message processing time (receive → acknowledge).

**PromQL**:
```promql
histogram_quantile(
  0.99,
  rate(relay_message_duration_seconds_bucket[5m])
)
```

**SLO**: < **200 ms** over a 30-day window

**Supplementary queries**:
```promql
# P95 latency (operational baseline)
histogram_quantile(0.95, rate(relay_message_duration_seconds_bucket[5m]))

# P50 latency (median)
histogram_quantile(0.50, rate(relay_message_duration_seconds_bucket[5m]))
```

**Error budget**: Defined as fraction of 5-minute windows where P99 exceeds 200 ms, not exceeding **0.5%** of windows in 30 days (~216 minutes of exceedance).

**Notes**:
- The RUNBOOKS.md threshold table lists p95 warning at 50 ms and critical at 200 ms. The SLO targets p99 < 200 ms — consistent with critical threshold being a hard SLO boundary.
- Latency spikes during SQLite vacuums are expected; schedule vacuums during low-traffic windows.

---

### SLI-4 — Federation Bidirectional Throughput Balance (TODO: placeholder)

> **TODO**: A proper federation delivery SLI requires a `relay_federation_offloads_acked_total`
> counter that is incremented when a peer relay explicitly acknowledges successful storage of an
> offloaded blob. This counter does not exist yet. Until it is added, SLI-4 is a **proxy
> metric** only — it measures bidirectional federation throughput balance, not delivery success.

**What it measures**: Ratio of inbound federation offloads to outbound federation offloads,
used as a federation health proxy. A balanced federation has roughly symmetric traffic; a
large imbalance may indicate a one-sided overload or peer rejection cascade. This does **not**
measure whether outbound offloads were successfully stored by peers.

**PromQL** (health proxy — not a true delivery SLI):
```promql
rate(relay_federation_offloads_received_total[5m])
/
rate(relay_federation_offloads_sent_total[5m])
```

**SLO**: Not applicable until `relay_federation_offloads_acked_total` is implemented.

**Notes**:
- Only applicable when `RELAY_FEDERATION_ENABLED=true`.
- To implement a true delivery SLI: add a `relay_federation_offloads_acked_total` counter
  incremented on receipt of an explicit ack message from the peer relay, then compute
  `rate(acked) / rate(sent)` as the delivery success fraction.
- Returns `NaN` when no federation traffic is present. Suppress alerts when `rate(relay_federation_offloads_sent_total[5m]) == 0`.

---

### SLI-5 — Zero Panics

**What it measures**: Cumulative panic count in the relay process.

**PromQL**:
```promql
relay_panics_total
```

**SLO**: `relay_panics_total` == **0** at all times in production

**Error budget**: None. Any panic is a P1 incident. The relay uses `panic=abort` in release mode, meaning a panic kills the process. systemd restarts within 5 seconds, but each restart is a brief outage and indicates a code defect.

---

## Measurement Windows

| SLI | Rate window | SLO compliance window |
|-----|-------------|-----------------------|
| Delivery success rate | 5m rolling | 30 days |
| Availability | 30s probe | 30 days |
| P99 latency | 5m rolling | 30 days |
| Federation throughput balance (proxy) | 5m rolling | N/A (pending ack counter) |
| Panics | instantaneous | rolling (any occurrence) |

---

## Error Budget Summary

| SLO | Target | Monthly error budget |
|-----|--------|---------------------|
| Delivery success | 99.9% | 43.2 min |
| Availability | 99.5% | 216 min |
| P99 latency | < 200ms | 216 min of windows |
| Federation throughput balance | N/A (proxy — pending ack counter) | N/A |
| Panics | 0 | 0 (no budget) |

---

## Alert Suggestions

Paste these into Alertmanager rules. Adjust `for` durations and routing to match your on-call setup.

### Alert: Delivery Success Rate Low

```yaml
- alert: RelayDeliverySuccessLow
  expr: |
    (
      1 - (
        rate(relay_messages_rejected_total[5m])
        / rate(relay_messages_received_total[5m])
      )
    ) < 0.999
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Relay delivery success below SLO (99.9%)"
    description: "Current rate {{ $value | humanizePercentage }}. Check relay_rate_limited_total and relay_messages_rejected_total."

- alert: RelayDeliverySuccessCritical
  expr: |
    (
      1 - (
        rate(relay_messages_rejected_total[5m])
        / rate(relay_messages_received_total[5m])
      )
    ) < 0.99
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Relay delivery success critically degraded (<99%)"
    description: "Immediate investigation required. See RUNBOOKS.md §2.2."
```

### Alert: Relay Down (Availability)

```yaml
- alert: RelayHealthEndpointDown
  expr: probe_success{job="vauchi-relay-health"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Relay /health endpoint is not responding"
    description: "External probe failed. Check systemd status and recent logs. See RUNBOOKS.md §1."
```

### Alert: P99 Latency High

```yaml
- alert: RelayLatencyP99High
  expr: |
    histogram_quantile(
      0.99,
      rate(relay_message_duration_seconds_bucket[5m])
    ) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Relay P99 latency above 100ms"
    description: "P99 is {{ $value | humanizeDuration }}. SLO breaches at 200ms."

- alert: RelayLatencyP99SLOBreach
  expr: |
    histogram_quantile(
      0.99,
      rate(relay_message_duration_seconds_bucket[5m])
    ) > 0.2
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Relay P99 latency breaching SLO (>200ms)"
    description: "P99 is {{ $value | humanizeDuration }}. Check for SQLite contention, connection storms."
```

### Alert: Federation Throughput Imbalance (proxy — not a delivery SLI)

> **Note**: This alert is a placeholder. It fires when inbound federation traffic is
> significantly below outbound, which may indicate peer rejections or connectivity issues.
> It does **not** confirm delivery success. Replace with an ack-based alert once
> `relay_federation_offloads_acked_total` is implemented.

```yaml
- alert: RelayFederationImbalanced
  expr: |
    (
      rate(relay_federation_offloads_received_total[5m])
      / rate(relay_federation_offloads_sent_total[5m])
    ) < 0.5
    and rate(relay_federation_offloads_sent_total[5m]) > 0
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Federation throughput heavily imbalanced (proxy metric)"
    description: "Inbound/outbound ratio {{ $value | humanizePercentage }}. Check peer connectivity and relay_federation_offloads_rejected_total. See RUNBOOKS.md §2.3 and §2.4."
```

### Alert: Panic Detected

```yaml
- alert: RelayPanicDetected
  expr: increase(relay_panics_total[5m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Relay process panic detected"
    description: "relay_panics_total has increased. Process may have restarted. See RUNBOOKS.md §2.5 for investigation steps."
```

---

## Grafana Dashboard

The pre-built dashboard at `deploy/grafana/relay-dashboard.json` includes panels for all SLIs above. Import it into Grafana and set the data source to your Prometheus instance.

Recommended dashboard variables:
- `$relay_job` — Prometheus job label for the relay scrape target
- `$probe_job` — Prometheus job label for the Blackbox Exporter probe

---

## Reference: All Relevant Metrics

| Metric | Type | Used in |
|--------|------|---------|
| `relay_messages_received_total` | Counter | SLI-1 |
| `relay_messages_rejected_total` | Counter | SLI-1 |
| `relay_message_duration_seconds` | Histogram | SLI-3 |
| `relay_panics_total` | Counter | SLI-5 |
| `relay_federation_offloads_sent_total` | Counter | SLI-4 |
| `relay_federation_offloads_received_total` | Counter | SLI-4 |
| `relay_federation_offloads_rejected_total` | Counter | SLI-4 context |
| `relay_rate_limited_total` | Counter | SLI-1 context |
| `relay_connections_active` | Gauge | operational |
| `relay_federation_peers_connected` | Gauge | operational |
| `relay_blobs_stored` | Gauge | capacity |

Metrics are exposed at `http://<host>:8081/metrics` in Prometheus text format.
