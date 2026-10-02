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
