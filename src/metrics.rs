// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus Metrics for Vauchi Relay
//!
//! Provides observability metrics for monitoring the relay server without
//! depending on the `prometheus` crate. The exposition format is the standard
//! Prometheus text format (`text/plain; version=0.0.4`), so scrapers continue
//! to work unchanged.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use parking_lot::Mutex;

/// Default histogram buckets matching the Prometheus client defaults.
const DEFAULT_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

// TODO(PFC): custom Prometheus client — see 2026-07-06-relay-pfc-violations R22
/// A metric family that can be serialized in Prometheus text format.
trait MetricFamily: Send + Sync {
    fn encode(&self, writer: &mut String);
}

/// Prometheus-style counter backed by an atomic u64.
#[derive(Clone)]
pub struct Counter {
    name: &'static str,
    help: &'static str,
    value: Arc<AtomicU64>,
}

impl Counter {
    fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment the counter by one.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Increment the counter by `v`.
    pub fn inc_by(&self, v: u64) {
        self.value.fetch_add(v, Ordering::Relaxed);
    }

    fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl MetricFamily for Counter {
    fn encode(&self, writer: &mut String) {
        writeln!(writer, "# HELP {} {}", self.name, self.help).unwrap();
        writeln!(writer, "# TYPE {} counter", self.name).unwrap();
        writeln!(writer, "{} {}", self.name, self.value()).unwrap();
    }
}

/// Prometheus-style gauge backed by an atomic i64.
#[derive(Clone)]
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: Arc<AtomicI64>,
}

impl Gauge {
    fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Set the gauge to `v`.
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Increment the gauge by one.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the gauge by one.
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Subtract `v` from the gauge.
    pub fn sub(&self, v: i64) {
        self.value.fetch_sub(v, Ordering::Relaxed);
    }

    fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl MetricFamily for Gauge {
    fn encode(&self, writer: &mut String) {
        writeln!(writer, "# HELP {} {}", self.name, self.help).unwrap();
        writeln!(writer, "# TYPE {} gauge", self.name).unwrap();
        writeln!(writer, "{} {}", self.name, self.value()).unwrap();
    }
}

// TODO(PFC): Histogram uses Mutex<f64> for sum — see 2026-07-06-relay-pfc-violations R11
/// Prometheus-style histogram backed by atomic bucket counts.
#[derive(Clone)]
pub struct Histogram {
    name: &'static str,
    help: &'static str,
    buckets: Vec<f64>,
    counts: Vec<Arc<AtomicU64>>,
    sum: Arc<Mutex<f64>>,
    count: Arc<AtomicU64>,
}

impl Histogram {
    fn new(name: &'static str, help: &'static str) -> Self {
        let counts = DEFAULT_BUCKETS
            .iter()
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();
        Self {
            name,
            help,
            buckets: DEFAULT_BUCKETS.to_vec(),
            counts,
            sum: Arc::new(Mutex::new(0.0)),
            count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Observe a value, updating all cumulative buckets.
    pub fn observe(&self, v: f64) {
        for (i, bucket) in self.buckets.iter().enumerate() {
            if v <= *bucket {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        *self.sum.lock() += v;
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn sum(&self) -> f64 {
        *self.sum.lock()
    }

    fn bucket_count(&self, idx: usize) -> u64 {
        self.counts[idx].load(Ordering::Relaxed)
    }
}

impl MetricFamily for Histogram {
    fn encode(&self, writer: &mut String) {
        writeln!(writer, "# HELP {} {}", self.name, self.help).unwrap();
        writeln!(writer, "# TYPE {} histogram", self.name).unwrap();
        for (i, bucket) in self.buckets.iter().enumerate() {
            writeln!(
                writer,
                "{}_bucket{{le=\"{}\"}} {}",
                self.name,
                format_bucket(*bucket),
                self.bucket_count(i)
            )
            .unwrap();
        }
        writeln!(
            writer,
            "{}_bucket{{le=\"+Inf\"}} {}",
            self.name,
            self.count()
        )
        .unwrap();
        writeln!(writer, "{}_sum {}", self.name, self.sum()).unwrap();
        writeln!(writer, "{}_count {}", self.name, self.count()).unwrap();
    }
}

fn format_bucket(v: f64) -> String {
    if v == v.trunc() {
        format!("{:.0}", v)
    } else {
        format!("{}", v)
    }
}

/// Registry of metric families.
struct Registry {
    families: Vec<Box<dyn MetricFamily>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            families: Vec::new(),
        }
    }

    fn register(&mut self, family: Box<dyn MetricFamily>) {
        self.families.push(family);
    }

    fn encode(&self) -> String {
        let mut writer = String::new();
        for family in &self.families {
            family.encode(&mut writer);
        }
        writer
    }
}

/// Metrics registry wrapper protected by a non-poisoning mutex.
type RegistryLock = Mutex<Registry>;

// TODO(PFC): /proc I/O and unsafe inside metric encoding — see 2026-07-06-relay-pfc-violations R10
/// Linux process metrics collector.
#[cfg(target_os = "linux")]
mod process {
    use super::MetricFamily;
    use std::fmt::Write;

    pub struct ProcessCollector;

    impl ProcessCollector {
        pub fn for_self() -> Box<dyn MetricFamily> {
            Box::new(ProcessMetrics)
        }
    }

    struct ProcessMetrics;

    impl MetricFamily for ProcessMetrics {
        fn encode(&self, writer: &mut String) {
            let stat = read_proc_self_stat();
            let ticks_per_sec = ticks_per_second();
            let page_size = page_size();

            let cpu_seconds = stat
                .as_ref()
                .map(|s| (s.utime + s.stime) as f64 / ticks_per_sec as f64)
                .unwrap_or(0.0);
            let vsize = stat.as_ref().map(|s| s.vsize).unwrap_or(0);
            let rss = stat.as_ref().map(|s| s.rss * page_size as i64).unwrap_or(0);
            let threads = stat.as_ref().map(|s| s.num_threads).unwrap_or(0);

            let open_fds = count_open_fds();
            let max_fds = read_max_fds();

            writeln!(
                writer,
                "# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds."
            )
            .unwrap();
            writeln!(writer, "# TYPE process_cpu_seconds_total counter").unwrap();
            writeln!(writer, "process_cpu_seconds_total {}", cpu_seconds).unwrap();

            writeln!(
                writer,
                "# HELP process_open_fds Number of open file descriptors."
            )
            .unwrap();
            writeln!(writer, "# TYPE process_open_fds gauge").unwrap();
            writeln!(writer, "process_open_fds {}", open_fds).unwrap();

            if let Some(max) = max_fds {
                writeln!(
                    writer,
                    "# HELP process_max_fds Maximum number of open file descriptors."
                )
                .unwrap();
                writeln!(writer, "# TYPE process_max_fds gauge").unwrap();
                writeln!(writer, "process_max_fds {}", max).unwrap();
            }

            writeln!(
                writer,
                "# HELP process_virtual_memory_bytes Virtual memory size in bytes."
            )
            .unwrap();
            writeln!(writer, "# TYPE process_virtual_memory_bytes gauge").unwrap();
            writeln!(writer, "process_virtual_memory_bytes {}", vsize).unwrap();

            writeln!(
                writer,
                "# HELP process_resident_memory_bytes Resident memory size in bytes."
            )
            .unwrap();
            writeln!(writer, "# TYPE process_resident_memory_bytes gauge").unwrap();
            writeln!(writer, "process_resident_memory_bytes {}", rss).unwrap();

            writeln!(
                writer,
                "# HELP process_threads Number of OS threads in the process."
            )
            .unwrap();
            writeln!(writer, "# TYPE process_threads gauge").unwrap();
            writeln!(writer, "process_threads {}", threads).unwrap();

            if let Some(start_time) = stat
                .as_ref()
                .and_then(|s| start_time_seconds(s, ticks_per_sec))
            {
                writeln!(
                    writer,
                    "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds."
                )
                .unwrap();
                writeln!(writer, "# TYPE process_start_time_seconds gauge").unwrap();
                writeln!(writer, "process_start_time_seconds {}", start_time).unwrap();
            }
        }
    }

    #[derive(Default)]
    struct ProcStat {
        utime: u64,
        stime: u64,
        starttime: u64,
        vsize: i64,
        rss: i64,
        num_threads: i64,
    }

    fn read_proc_self_stat() -> Option<ProcStat> {
        let contents = std::fs::read_to_string("/proc/self/stat").ok()?;
        let after_comm = contents.rfind(')')?;
        let fields: Vec<&str> = contents[after_comm + 2..].split_whitespace().collect();
        if fields.len() < 20 {
            return None;
        }
        Some(ProcStat {
            utime: fields[11].parse().unwrap_or(0),
            stime: fields[12].parse().unwrap_or(0),
            num_threads: fields[17].parse().unwrap_or(0),
            starttime: fields[19].parse().unwrap_or(0),
            vsize: fields[20].parse().unwrap_or(0),
            rss: fields[21].parse().unwrap_or(0),
        })
    }

    fn ticks_per_second() -> u64 {
        // SAFETY: sysconf is thread-safe and returns a long.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks <= 0 { 100 } else { ticks as u64 }
    }

    fn page_size() -> u64 {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 { 4096 } else { size as u64 }
    }

    fn count_open_fds() -> i64 {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.filter_map(|e| e.ok()).count() as i64)
            .unwrap_or(0)
    }

    fn read_max_fds() -> Option<i64> {
        let contents = std::fs::read_to_string("/proc/self/limits").ok()?;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("Max open files") {
                return rest.split_whitespace().nth(2).and_then(|s| s.parse().ok());
            }
        }
        None
    }

    fn start_time_seconds(stat: &ProcStat, ticks_per_sec: u64) -> Option<i64> {
        let btime = std::fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find(|line| line.starts_with("btime "))?
            .split_whitespace()
            .nth(1)?
            .parse::<i64>()
            .ok()?;
        Some(btime + (stat.starttime as f64 / ticks_per_sec as f64) as i64)
    }
}

/// Relay server metrics.
#[derive(Clone)]
pub struct RelayMetrics {
    /// Registry for all metrics.
    registry: Arc<RegistryLock>,

    // Connection metrics
    /// Total WebSocket connections accepted.
    pub connections_total: Counter,
    /// Current active WebSocket connections.
    pub connections_active: Gauge,
    /// Connection errors (handshake failures, etc.).
    pub connection_errors: Counter,

    // Message metrics
    /// Total messages received.
    pub messages_received: Counter,
    /// Total messages sent.
    pub messages_sent: Counter,
    /// Messages rejected (rate limited, too large, etc.).
    pub messages_rejected: Counter,
    /// Message processing duration in seconds.
    pub message_duration: Histogram,

    // Storage metrics
    /// Current number of stored blobs.
    pub blobs_stored: Gauge,
    /// Total blobs created.
    pub blobs_created: Counter,
    /// Total blobs delivered (taken).
    pub blobs_delivered: Counter,
    /// Total blobs expired and cleaned up.
    pub blobs_expired: Counter,

    // Recovery metrics
    /// Active recovery proofs.
    pub recovery_proofs_active: Gauge,
    /// Total recovery vouchers received.
    pub recovery_vouchers_total: Counter,

    // Rate limiting
    /// Requests rate limited.
    pub rate_limited: Counter,

    // Runtime
    /// Total panics caught by the panic hook.
    pub panics_total: Counter,

    // Federation metrics
    /// Current active peer connections.
    pub federation_peers_connected: Gauge,
    /// Total outbound peer connection attempts.
    pub federation_peer_connections_total: Counter,
    /// Total peer connection errors.
    pub federation_peer_connection_errors: Counter,
    /// Total blobs offloaded to peers (outbound).
    pub federation_offloads_sent: Counter,
    /// Total blobs received from peers (inbound).
    pub federation_offloads_received: Counter,
    /// Total inbound offloads rejected (hop count, integrity, capacity).
    pub federation_offloads_rejected: Counter,
    /// Current active forwarding hints.
    pub federation_hints_active: Gauge,
    /// Total forwarding hints stored.
    pub federation_hints_stored: Counter,
    /// Total forwarding hints expired.
    pub federation_hints_expired: Counter,
    /// Total drain notices received from peers.
    pub federation_drain_notices: Counter,
    /// Total peer rate-limited messages.
    pub federation_rate_limited: Counter,
    /// Total peer version handshakes received (accepted or rejected).
    pub federation_handshakes_received: Counter,
    /// Total inbound envelopes refused for a protocol version mismatch.
    pub federation_version_rejected: Counter,
    /// Total inbound payloads ignored as unknown/unhandled (forward compat).
    pub federation_unknown_payloads: Counter,

    // Tokio runtime metrics
    /// Number of alive async tasks in the tokio runtime.
    pub tokio_alive_tasks: Gauge,
    /// Number of worker threads in the tokio runtime.
    pub tokio_workers: Gauge,
}

impl RelayMetrics {
    /// Creates a new metrics instance with all counters registered.
    pub fn new() -> Self {
        let mut registry = Registry::new();

        let connections_total = Counter::new(
            "relay_connections_total",
            "Total WebSocket connections accepted",
        );
        let connections_active = Gauge::new(
            "relay_connections_active",
            "Current active WebSocket connections",
        );
        let connection_errors =
            Counter::new("relay_connection_errors_total", "Total connection errors");

        let messages_received =
            Counter::new("relay_messages_received_total", "Total messages received");
        let messages_sent = Counter::new("relay_messages_sent_total", "Total messages sent");
        let messages_rejected =
            Counter::new("relay_messages_rejected_total", "Total messages rejected");
        let message_duration = Histogram::new(
            "relay_message_duration_seconds",
            "Message processing duration in seconds",
        );

        let blobs_stored = Gauge::new("relay_blobs_stored", "Current number of stored blobs");
        let blobs_created = Counter::new("relay_blobs_created_total", "Total blobs created");
        let blobs_delivered = Counter::new("relay_blobs_delivered_total", "Total blobs delivered");
        let blobs_expired = Counter::new(
            "relay_blobs_expired_total",
            "Total blobs expired and cleaned up",
        );

        let recovery_proofs_active = Gauge::new(
            "relay_recovery_proofs_active",
            "Current active recovery proofs",
        );
        let recovery_vouchers_total = Counter::new(
            "relay_recovery_vouchers_total",
            "Total recovery vouchers received",
        );

        let rate_limited = Counter::new("relay_rate_limited_total", "Total requests rate limited");
        let panics_total = Counter::new("relay_panics_total", "Total panics caught by panic hook");

        let federation_peers_connected = Gauge::new(
            "relay_federation_peers_connected",
            "Current active peer connections",
        );
        let federation_peer_connections_total = Counter::new(
            "relay_federation_peer_connections_total",
            "Total outbound peer connection attempts",
        );
        let federation_peer_connection_errors = Counter::new(
            "relay_federation_peer_connection_errors_total",
            "Total peer connection errors",
        );
        let federation_offloads_sent = Counter::new(
            "relay_federation_offloads_sent_total",
            "Total blobs offloaded to peers",
        );
        let federation_offloads_received = Counter::new(
            "relay_federation_offloads_received_total",
            "Total blobs received from peers",
        );
        let federation_offloads_rejected = Counter::new(
            "relay_federation_offloads_rejected_total",
            "Total inbound offloads rejected",
        );
        let federation_hints_active = Gauge::new(
            "relay_federation_hints_active",
            "Current active forwarding hints",
        );
        let federation_hints_stored = Counter::new(
            "relay_federation_hints_stored_total",
            "Total forwarding hints stored",
        );
        let federation_hints_expired = Counter::new(
            "relay_federation_hints_expired_total",
            "Total forwarding hints expired",
        );
        let federation_drain_notices = Counter::new(
            "relay_federation_drain_notices_total",
            "Total drain notices received from peers",
        );
        let federation_rate_limited = Counter::new(
            "relay_federation_rate_limited_total",
            "Total peer rate-limited messages",
        );
        let federation_handshakes_received = Counter::new(
            "relay_federation_handshakes_received_total",
            "Total peer version handshakes received (accepted or rejected)",
        );
        let federation_version_rejected = Counter::new(
            "relay_federation_version_rejected_total",
            "Total inbound envelopes refused for a protocol version mismatch",
        );
        let federation_unknown_payloads = Counter::new(
            "relay_federation_unknown_payloads_total",
            "Total inbound payloads ignored as unknown/unhandled (forward compat)",
        );

        let tokio_alive_tasks = Gauge::new(
            "relay_tokio_alive_tasks",
            "Number of alive async tasks in the tokio runtime",
        );
        let tokio_workers = Gauge::new(
            "relay_tokio_workers",
            "Number of worker threads in the tokio runtime",
        );

        // Register process metrics on Linux.
        #[cfg(target_os = "linux")]
        registry.register(process::ProcessCollector::for_self());

        registry.register(Box::new(connections_total.clone()));
        registry.register(Box::new(connections_active.clone()));
        registry.register(Box::new(connection_errors.clone()));
        registry.register(Box::new(messages_received.clone()));
        registry.register(Box::new(messages_sent.clone()));
        registry.register(Box::new(messages_rejected.clone()));
        registry.register(Box::new(message_duration.clone()));
        registry.register(Box::new(blobs_stored.clone()));
        registry.register(Box::new(blobs_created.clone()));
        registry.register(Box::new(blobs_delivered.clone()));
        registry.register(Box::new(blobs_expired.clone()));
        registry.register(Box::new(recovery_proofs_active.clone()));
        registry.register(Box::new(recovery_vouchers_total.clone()));
        registry.register(Box::new(rate_limited.clone()));
        registry.register(Box::new(panics_total.clone()));
        registry.register(Box::new(federation_peers_connected.clone()));
        registry.register(Box::new(federation_peer_connections_total.clone()));
        registry.register(Box::new(federation_peer_connection_errors.clone()));
        registry.register(Box::new(federation_offloads_sent.clone()));
        registry.register(Box::new(federation_offloads_received.clone()));
        registry.register(Box::new(federation_offloads_rejected.clone()));
        registry.register(Box::new(federation_hints_active.clone()));
        registry.register(Box::new(federation_hints_stored.clone()));
        registry.register(Box::new(federation_hints_expired.clone()));
        registry.register(Box::new(federation_drain_notices.clone()));
        registry.register(Box::new(federation_rate_limited.clone()));
        registry.register(Box::new(federation_handshakes_received.clone()));
        registry.register(Box::new(federation_version_rejected.clone()));
        registry.register(Box::new(federation_unknown_payloads.clone()));
        registry.register(Box::new(tokio_alive_tasks.clone()));
        registry.register(Box::new(tokio_workers.clone()));

        Self {
            registry: Arc::new(Mutex::new(registry)),
            connections_total,
            connections_active,
            connection_errors,
            messages_received,
            messages_sent,
            messages_rejected,
            message_duration,
            blobs_stored,
            blobs_created,
            blobs_delivered,
            blobs_expired,
            recovery_proofs_active,
            recovery_vouchers_total,
            rate_limited,
            panics_total,
            federation_peers_connected,
            federation_peer_connections_total,
            federation_peer_connection_errors,
            federation_offloads_sent,
            federation_offloads_received,
            federation_offloads_rejected,
            federation_hints_active,
            federation_hints_stored,
            federation_hints_expired,
            federation_drain_notices,
            federation_rate_limited,
            federation_handshakes_received,
            federation_version_rejected,
            federation_unknown_payloads,
            tokio_alive_tasks,
            tokio_workers,
        }
    }

    /// Encodes all metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        self.registry.lock().encode()
    }
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// INLINE_TEST_REQUIRED: unit tests for the internal metrics encoder verify
// Prometheus text format, histogram math, and process-metric formatting.
#[cfg(test)]
mod tests {
    use super::*;

    // @internal
    #[test]
    fn counter_increments_and_encodes() {
        let counter = Counter::new("test_counter", "A test counter");
        counter.inc();
        counter.inc_by(2);

        let mut writer = String::new();
        counter.encode(&mut writer);
        assert!(writer.contains("# HELP test_counter A test counter"));
        assert!(writer.contains("# TYPE test_counter counter"));
        assert!(writer.contains("test_counter 3"));
    }

    // @internal
    #[test]
    fn gauge_set_and_encodes() {
        let gauge = Gauge::new("test_gauge", "A test gauge");
        gauge.set(42);
        gauge.dec();
        gauge.sub(2);

        let mut writer = String::new();
        gauge.encode(&mut writer);
        assert!(writer.contains("# HELP test_gauge A test gauge"));
        assert!(writer.contains("# TYPE test_gauge gauge"));
        assert!(writer.contains("test_gauge 39"));
    }

    // @internal
    #[test]
    fn histogram_observes_sum_count_and_buckets() {
        let hist = Histogram::new("test_hist", "A test histogram");
        hist.observe(0.01); // in first bucket (0.005? no, 0.01 <= 0.01)
        hist.observe(0.1); // <= 0.1
        hist.observe(1.0); // <= 1.0
        hist.observe(5.0); // <= 5.0

        assert_eq!(hist.count(), 4);
        assert!((hist.sum() - 6.11).abs() < f64::EPSILON * 10.0);

        // Bucket counts are cumulative.
        let first_bucket = hist.bucket_count(0); // le="0.005"
        let le_0_01 = hist.bucket_count(1); // le="0.01"
        let le_0_1 = hist.bucket_count(4); // le="0.1"
        let le_0_5 = hist.bucket_count(6); // le="0.5"
        let le_1 = hist.bucket_count(7); // le="1"
        let le_2_5 = hist.bucket_count(8); // le="2.5"
        let le_5 = hist.bucket_count(9); // le="5"
        assert_eq!(first_bucket, 0);
        assert_eq!(le_0_01, 1);
        assert_eq!(le_0_1, 2);
        assert_eq!(le_0_5, 2);
        assert_eq!(le_1, 3);
        assert_eq!(le_2_5, 3);
        assert_eq!(le_5, 4);

        let mut writer = String::new();
        hist.encode(&mut writer);
        assert!(writer.contains("# HELP test_hist A test histogram"));
        assert!(writer.contains("# TYPE test_hist histogram"));
        assert!(writer.contains("test_hist_bucket{le=\"+Inf\"} 4"));
        assert!(writer.contains("test_hist_sum 6.11"));
        assert!(writer.contains("test_hist_count 4"));
    }

    // @internal
    #[test]
    fn registry_encodes_multiple_families() {
        let mut registry = Registry::new();
        let counter = Counter::new("reg_counter", "counter help");
        let gauge = Gauge::new("reg_gauge", "gauge help");
        counter.inc();
        gauge.set(7);
        registry.register(Box::new(counter));
        registry.register(Box::new(gauge));

        let output = registry.encode();
        assert!(output.contains("reg_counter 1"));
        assert!(output.contains("reg_gauge 7"));
    }

    // @internal
    #[test]
    fn relay_metrics_encode_has_no_double_blank_lines() {
        let metrics = RelayMetrics::new();
        let output = metrics.encode();
        assert!(
            !output.contains("\n\n"),
            "encoded metrics should not contain blank lines:\n{output}"
        );
    }

    // @internal
    #[cfg(target_os = "linux")]
    #[test]
    fn relay_metrics_include_linux_process_metrics() {
        let metrics = RelayMetrics::new();
        let output = metrics.encode();
        assert!(output.contains("process_cpu_seconds_total"));
        assert!(output.contains("process_open_fds"));
        assert!(output.contains("process_virtual_memory_bytes"));
        assert!(output.contains("process_resident_memory_bytes"));
        assert!(output.contains("process_threads"));
    }
}
