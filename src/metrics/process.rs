// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Linux process metrics, read from `/proc`.
//!
//! Reading ([`ProcessSnapshot::read`]) is kept apart from parsing and
//! encoding, which are pure and tested on fixed input
//! (relay-pfc-violations R10).

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
        ProcessSnapshot::read().encode(writer);
    }
}

/// The values exported for this process at one instant.
#[derive(Debug, PartialEq)]
struct ProcessSnapshot {
    cpu_seconds: f64,
    open_fds: i64,
    max_fds: Option<i64>,
    virtual_memory_bytes: i64,
    resident_memory_bytes: i64,
    threads: i64,
    start_time_seconds: Option<i64>,
}

impl ProcessSnapshot {
    fn read() -> Self {
        let stat = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|contents| parse_proc_self_stat(&contents));
        let boot_time = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|contents| parse_boot_time(&contents));
        let max_fds = std::fs::read_to_string("/proc/self/limits")
            .ok()
            .and_then(|contents| parse_max_open_files(&contents));
        Self::from_parts(
            stat.as_ref(),
            ticks_per_second(),
            page_size(),
            count_open_fds(),
            max_fds,
            boot_time,
        )
    }

    fn from_parts(
        stat: Option<&ProcStat>,
        ticks_per_sec: u64,
        page_size: u64,
        open_fds: i64,
        max_fds: Option<i64>,
        boot_time: Option<i64>,
    ) -> Self {
        Self {
            cpu_seconds: stat
                .map(|s| (s.utime + s.stime) as f64 / ticks_per_sec as f64)
                .unwrap_or(0.0),
            open_fds,
            max_fds,
            virtual_memory_bytes: stat.map(|s| s.vsize).unwrap_or(0),
            resident_memory_bytes: stat.map(|s| s.rss * page_size as i64).unwrap_or(0),
            threads: stat.map(|s| s.num_threads).unwrap_or(0),
            start_time_seconds: stat.zip(boot_time).map(|(s, boot_time)| {
                boot_time + (s.starttime as f64 / ticks_per_sec as f64) as i64
            }),
        }
    }

    fn encode(&self, writer: &mut String) {
        writeln!(
            writer,
            "# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds."
        )
        .unwrap();
        writeln!(writer, "# TYPE process_cpu_seconds_total counter").unwrap();
        writeln!(writer, "process_cpu_seconds_total {}", self.cpu_seconds).unwrap();

        writeln!(
            writer,
            "# HELP process_open_fds Number of open file descriptors."
        )
        .unwrap();
        writeln!(writer, "# TYPE process_open_fds gauge").unwrap();
        writeln!(writer, "process_open_fds {}", self.open_fds).unwrap();

        if let Some(max) = self.max_fds {
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
        writeln!(
            writer,
            "process_virtual_memory_bytes {}",
            self.virtual_memory_bytes
        )
        .unwrap();

        writeln!(
            writer,
            "# HELP process_resident_memory_bytes Resident memory size in bytes."
        )
        .unwrap();
        writeln!(writer, "# TYPE process_resident_memory_bytes gauge").unwrap();
        writeln!(
            writer,
            "process_resident_memory_bytes {}",
            self.resident_memory_bytes
        )
        .unwrap();

        writeln!(
            writer,
            "# HELP process_threads Number of OS threads in the process."
        )
        .unwrap();
        writeln!(writer, "# TYPE process_threads gauge").unwrap();
        writeln!(writer, "process_threads {}", self.threads).unwrap();

        if let Some(start_time) = self.start_time_seconds {
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

#[derive(Debug, Default, PartialEq)]
struct ProcStat {
    utime: u64,
    stime: u64,
    starttime: u64,
    vsize: i64,
    rss: i64,
    num_threads: i64,
}

/// Parses the contents of `/proc/<pid>/stat`.
fn parse_proc_self_stat(contents: &str) -> Option<ProcStat> {
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

/// Parses the open-files limit out of the contents of `/proc/<pid>/limits`.
fn parse_max_open_files(limits: &str) -> Option<i64> {
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix("Max open files") {
            return rest.split_whitespace().nth(2).and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Parses the boot time (seconds since the epoch) out of `/proc/stat`.
fn parse_boot_time(proc_stat: &str) -> Option<i64> {
    proc_stat
        .lines()
        .find(|line| line.starts_with("btime "))?
        .split_whitespace()
        .nth(1)?
        .parse::<i64>()
        .ok()
}

fn ticks_per_second() -> u64 {
    // SAFETY: sysconf is thread-safe and returns a long.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 { 100 } else { ticks as u64 }
}

fn page_size() -> u64 {
    // SAFETY: sysconf is thread-safe and returns a long.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 { 4096 } else { size as u64 }
}

fn count_open_fds() -> i64 {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(|e| e.ok()).count() as i64)
        .unwrap_or(0)
}

// INLINE_TEST_REQUIRED: the parsers and ProcessSnapshot are private to
// this module; only the encoded text leaves it.
#[cfg(test)]
mod tests {
    use super::*;

    // The command name holds spaces and parentheses on purpose: fields
    // are counted from the LAST ')'.
    const STAT: &str = "4242 (relay (test) x) S 1 4242 4242 0 -1 4194304 500 0 0 0 150 50 0 0 \
                        20 0 7 0 9000 123456789 2500 18446744073709551615 1 1 0 0 0 0 0\n";

    fn parsed_stat() -> ProcStat {
        ProcStat {
            utime: 150,
            stime: 50,
            starttime: 9000,
            vsize: 123_456_789,
            rss: 2500,
            num_threads: 7,
        }
    }

    // @internal
    #[test]
    fn stat_line_yields_the_exported_fields_whatever_the_command_name() {
        assert_eq!(parse_proc_self_stat(STAT), Some(parsed_stat()));
    }

    // @internal
    #[test]
    fn stat_line_cut_off_after_a_few_fields_is_rejected() {
        assert_eq!(parse_proc_self_stat("4242 (relay) S 1 4242 4242"), None);
    }

    // @internal
    #[test]
    fn boot_time_is_read_from_the_btime_line() {
        let proc_stat = "cpu  1 2 3 4\nbtime 1700000000\nprocesses 5\n";

        assert_eq!(parse_boot_time(proc_stat), Some(1_700_000_000));
        assert_eq!(parse_boot_time("cpu  1 2 3 4\n"), None);
    }

    // @internal
    #[test]
    fn snapshot_converts_ticks_to_seconds_and_pages_to_bytes() {
        let snapshot = ProcessSnapshot::from_parts(
            Some(&parsed_stat()),
            100,
            4096,
            12,
            Some(1024),
            Some(1_700_000_000),
        );

        assert_eq!(
            snapshot,
            ProcessSnapshot {
                cpu_seconds: 2.0,
                open_fds: 12,
                max_fds: Some(1024),
                virtual_memory_bytes: 123_456_789,
                resident_memory_bytes: 10_240_000,
                threads: 7,
                start_time_seconds: Some(1_700_000_090),
            }
        );
    }

    // @internal
    #[test]
    fn snapshot_without_a_stat_line_reports_zeros_and_no_start_time() {
        let snapshot = ProcessSnapshot::from_parts(None, 100, 4096, 12, None, Some(1_700_000_000));

        assert_eq!(
            snapshot,
            ProcessSnapshot {
                cpu_seconds: 0.0,
                open_fds: 12,
                max_fds: None,
                virtual_memory_bytes: 0,
                resident_memory_bytes: 0,
                threads: 0,
                start_time_seconds: None,
            }
        );
    }

    // @internal
    #[test]
    fn snapshot_encodes_every_metric_with_its_value() {
        let snapshot = ProcessSnapshot {
            cpu_seconds: 2.5,
            open_fds: 12,
            max_fds: Some(1024),
            virtual_memory_bytes: 123_456_789,
            resident_memory_bytes: 10_240_000,
            threads: 7,
            start_time_seconds: Some(1_700_000_090),
        };
        let mut text = String::new();

        snapshot.encode(&mut text);

        let values: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            values,
            vec![
                "process_cpu_seconds_total 2.5",
                "process_open_fds 12",
                "process_max_fds 1024",
                "process_virtual_memory_bytes 123456789",
                "process_resident_memory_bytes 10240000",
                "process_threads 7",
                "process_start_time_seconds 1700000090",
            ]
        );
        assert_eq!(text.lines().filter(|l| l.starts_with("# TYPE")).count(), 7);
    }

    // @internal
    #[test]
    fn snapshot_omits_the_metrics_it_has_no_value_for() {
        let snapshot = ProcessSnapshot::from_parts(None, 100, 4096, 12, None, None);
        let mut text = String::new();

        snapshot.encode(&mut text);

        assert!(!text.contains("process_max_fds"));
        assert!(!text.contains("process_start_time_seconds"));
    }

    // Reads the real /proc of the test process: this is what pins the
    // file paths, sysconf calls and fd counting, which no fixture reaches.
    // @internal
    #[test]
    fn snapshot_read_from_proc_describes_this_process() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let snapshot = ProcessSnapshot::read();

        assert!(snapshot.open_fds >= 3, "open fds: {}", snapshot.open_fds);
        assert!(snapshot.threads >= 1, "threads: {}", snapshot.threads);
        assert!(
            snapshot.resident_memory_bytes >= 1 << 20,
            "resident bytes: {}",
            snapshot.resident_memory_bytes
        );
        assert!(snapshot.virtual_memory_bytes > snapshot.resident_memory_bytes);
        let started = snapshot.start_time_seconds.unwrap();
        assert!(
            (now - 3600..=now + 1).contains(&started),
            "start time {started} is not within the last hour before {now}"
        );
    }
}
