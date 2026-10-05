// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-window OHTTP key seeds (#288, ADR-037 addendum 2026-10-05).
//!
//! The gateway serves one key per 24 h UTC window. Each window's key is
//! derived from its own random seed — never from a long-lived secret, so a
//! stolen file opens at most the three windows it holds. The previous,
//! current and next window are kept on disk, so a restart keeps the keys
//! clients already hold.
//!
//! File layout: `VOW1` | count (1) | count × (window u64 BE | seed 32).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use rand::RngCore;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::ohttp_gateway::OhttpGatewayError;

const MAGIC: &[u8; 4] = b"VOW1";
const SEED_BYTES: usize = 32;
const ENTRY_BYTES: usize = 8 + SEED_BYTES;

/// The seeds for the windows around the current one.
pub struct WindowSeeds {
    seeds: BTreeMap<u64, Zeroizing<[u8; SEED_BYTES]>>,
}

impl WindowSeeds {
    /// Load the seed file, keep the seeds for `current_window` ±1, create the
    /// missing ones and persist the result. A missing, legacy or corrupt
    /// file starts fresh.
    pub fn load_or_create(path: &Path, current_window: u64) -> Result<Self, OhttpGatewayError> {
        let seeds = match std::fs::read(path) {
            Ok(bytes) => parse(&bytes).unwrap_or_else(|| {
                warn!(
                    "OHTTP window seed file {} is not a window store (legacy or corrupt); starting fresh",
                    path.display()
                );
                BTreeMap::new()
            }),
            Err(_) => BTreeMap::new(),
        };
        let mut store = Self { seeds };
        store.retain_and_fill(current_window);
        store.persist(path)?;
        Ok(store)
    }

    /// Move to `current_window`: drop windows older than its predecessor and
    /// add the missing ones. Persists and returns `true` if anything changed.
    pub fn advance(&mut self, path: &Path, current_window: u64) -> Result<bool, OhttpGatewayError> {
        let before: Vec<u64> = self.windows();
        self.retain_and_fill(current_window);
        if self.windows() == before {
            return Ok(false);
        }
        self.persist(path)?;
        info!(current_window, "OHTTP window keys advanced");
        Ok(true)
    }

    /// The windows held, oldest first.
    pub fn windows(&self) -> Vec<u64> {
        self.seeds.keys().copied().collect()
    }

    /// The seed for `window`, if held.
    pub fn seed(&self, window: u64) -> Option<&[u8; SEED_BYTES]> {
        self.seeds.get(&window).map(|seed| &**seed)
    }

    fn retain_and_fill(&mut self, current_window: u64) {
        let wanted = current_window.saturating_sub(1)..=current_window.saturating_add(1);
        self.seeds.retain(|window, _| wanted.contains(window));
        for window in wanted {
            self.seeds.entry(window).or_insert_with(random_seed);
        }
    }

    fn persist(&self, path: &Path) -> Result<(), OhttpGatewayError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(5 + self.seeds.len() * ENTRY_BYTES));
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.seeds.len() as u8);
        for (window, seed) in &self.seeds {
            bytes.extend_from_slice(&window.to_be_bytes());
            bytes.extend_from_slice(&seed[..]);
        }
        write_owner_only(path, &bytes)
    }
}

impl std::fmt::Debug for WindowSeeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowSeeds")
            .field("windows", &self.windows())
            .finish()
    }
}

// TODO(PFC): random key material generated internally — see 2026-07-06-relay-pfc-violations R19
fn random_seed() -> Zeroizing<[u8; SEED_BYTES]> {
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    rand::rngs::OsRng.fill_bytes(&mut seed[..]);
    seed
}

fn parse(bytes: &[u8]) -> Option<BTreeMap<u64, Zeroizing<[u8; SEED_BYTES]>>> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let (&count, entries) = rest.split_first()?;
    if entries.len() != usize::from(count) * ENTRY_BYTES {
        return None;
    }
    let mut seeds = BTreeMap::new();
    for entry in entries.chunks_exact(ENTRY_BYTES) {
        let window = u64::from_be_bytes(entry[..8].try_into().ok()?);
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        seed.copy_from_slice(&entry[8..]);
        seeds.insert(window, seed);
    }
    Some(seeds)
}

/// Write via a sibling temp file created owner-only, then rename, so the
/// seeds are never world-readable and never half-written.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), OhttpGatewayError> {
    let io = |e: std::io::Error| OhttpGatewayError::Io(format!("OHTTP window seed file: {e}"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }
    Ok(())
}
