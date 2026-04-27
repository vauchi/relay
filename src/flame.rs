// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tracing-flame layer setup for relay profiling.
//!
//! Compiled only with the `flame` feature. The returned [`FlushGuard`]
//! must be held for the lifetime of the relay process (held in `main`)
//! so the buffered writer flushes on shutdown.
//!
//! Output: `$VAUCHI_FLAME_OUT` (full path) or
//! `<CARGO_MANIFEST_DIR>/artifacts/flame/relay-<ts>.folded`.

use std::fs::File;
use std::path::PathBuf;

use tracing_flame::FlameLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const DEFAULT_FILTER: &str = "info,vauchi_relay=trace,vauchi_protocol=trace";

/// Install the global subscriber with both fmt + flame layers.
///
/// Writes are unbuffered (no [`BufWriter`]) so the trace flushes even when
/// the relay is killed via signal without normal Drop ordering.
pub fn init() {
    let path = output_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("flame: create {} failed: {e}", parent.display()));
    }
    let file = File::create(&path)
        .unwrap_or_else(|e| panic!("flame: open {} failed: {e}", path.display()));
    let flame_layer = FlameLayer::new(file);

    let filter = std::env::var("VAUCHI_FLAME_FILTER")
        .ok()
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER));

    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(flame_layer)
        .try_init()
        .ok();

    eprintln!("[flame] writing folded trace -> {}", path.display());
}

fn output_path() -> PathBuf {
    if let Ok(p) = std::env::var("VAUCHI_FLAME_OUT") {
        return PathBuf::from(p);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("artifacts/flame")
        .join(format!("relay-{ts}.folded"))
}
