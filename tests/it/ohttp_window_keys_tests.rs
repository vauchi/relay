// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway's per-window key seeds (#288): one random seed per window for
//! the previous, current and next window, kept across restarts.

use std::path::Path;

use vauchi_relay::ohttp_window_keys::WindowSeeds;

const CURRENT: u64 = 20_366;

fn seeds_of(store: &WindowSeeds) -> Vec<(u64, [u8; 32])> {
    store
        .windows()
        .into_iter()
        .map(|window| (window, *store.seed(window).expect("seed for listed window")))
        .collect()
}

fn store_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("ohttp-window-seeds.bin")
}

// @internal
#[test]
fn a_fresh_start_holds_the_previous_current_and_next_window() {
    let dir = tempfile::tempdir().unwrap();

    let store = WindowSeeds::load_or_create(&store_in(&dir), CURRENT).unwrap();

    assert_eq!(store.windows(), vec![CURRENT - 1, CURRENT, CURRENT + 1]);
}

#[cfg(unix)]
// @internal
#[test]
fn the_seed_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);

    WindowSeeds::load_or_create(&path, CURRENT).unwrap();

    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// The regression windowed keys exist to avoid: a restart must not drop the
/// keys clients already hold.
// @internal
#[test]
fn a_restart_reloads_the_same_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let before = seeds_of(&WindowSeeds::load_or_create(&path, CURRENT).unwrap());

    let after = seeds_of(&WindowSeeds::load_or_create(&path, CURRENT).unwrap());

    assert_eq!(after, before);
}

// @internal
#[test]
fn every_window_has_its_own_seed() {
    let dir = tempfile::tempdir().unwrap();

    let seeds = seeds_of(&WindowSeeds::load_or_create(&store_in(&dir), CURRENT).unwrap());

    assert_ne!(seeds[0].1, seeds[1].1);
    assert_ne!(seeds[1].1, seeds[2].1);
    assert_ne!(seeds[0].1, seeds[2].1);
}

// @internal
#[test]
fn advancing_drops_the_oldest_keeps_the_rest_and_adds_the_next() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let mut store = WindowSeeds::load_or_create(&path, CURRENT).unwrap();
    let before = seeds_of(&store);

    let changed = store.advance(&path, CURRENT + 1).unwrap();

    assert!(changed, "a new window must change the store");
    assert_eq!(store.windows(), vec![CURRENT, CURRENT + 1, CURRENT + 2]);
    assert_eq!(&seeds_of(&store)[..2], &before[1..]);
    assert_eq!(
        seeds_of(&WindowSeeds::load_or_create(&path, CURRENT + 1).unwrap()),
        seeds_of(&store),
        "the advanced store is what a restart reloads"
    );
}

// @internal
#[test]
fn advancing_within_the_same_window_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let mut store = WindowSeeds::load_or_create(&path, CURRENT).unwrap();
    let before = seeds_of(&store);

    let changed = store.advance(&path, CURRENT).unwrap();

    assert!(!changed);
    assert_eq!(seeds_of(&store), before);
}

// @internal
#[test]
fn a_restart_after_a_long_gap_starts_fresh_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let old = seeds_of(&WindowSeeds::load_or_create(&path, CURRENT).unwrap());

    let store = WindowSeeds::load_or_create(&path, CURRENT + 7).unwrap();

    assert_eq!(store.windows(), vec![CURRENT + 6, CURRENT + 7, CURRENT + 8]);
    for (_, seed) in seeds_of(&store) {
        assert!(
            old.iter().all(|(_, o)| *o != seed),
            "no seed survives a week"
        );
    }
}

/// Loads the store twice: a replaced file must start fresh windows and
/// persist them, so the second load sees the first load's seeds.
fn load_twice(path: &Path) -> (WindowSeeds, WindowSeeds) {
    let first = WindowSeeds::load_or_create(path, CURRENT).unwrap();
    let again = WindowSeeds::load_or_create(path, CURRENT).unwrap();
    (first, again)
}

/// Today's single-seed file (32 bytes) migrates to the window store.
// @internal
#[test]
fn a_legacy_single_seed_file_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let legacy_seed = [0x42u8; 32];
    std::fs::write(&path, legacy_seed).unwrap();

    let (store, reloaded) = load_twice(&path);

    assert_eq!(store.windows(), vec![CURRENT - 1, CURRENT, CURRENT + 1]);
    assert!(
        seeds_of(&store)
            .iter()
            .all(|(_, seed)| *seed != legacy_seed)
    );
    assert_eq!(seeds_of(&reloaded), seeds_of(&store));
}

// @internal
#[test]
fn a_corrupt_file_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    std::fs::write(&path, b"VOW1\x09not-a-seed-file").unwrap();

    let (store, reloaded) = load_twice(&path);

    assert_eq!(store.windows(), vec![CURRENT - 1, CURRENT, CURRENT + 1]);
    assert_eq!(seeds_of(&reloaded), seeds_of(&store));
}

/// DC-05: seeds never reach logs.
// @internal
#[test]
fn debug_shows_windows_not_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let store = WindowSeeds::load_or_create(&store_in(&dir), CURRENT).unwrap();
    let seed_hex: String = store
        .seed(CURRENT)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let debug = format!("{store:?}");

    assert_eq!(
        debug,
        format!(
            "WindowSeeds {{ windows: [{}, {}, {}] }}",
            CURRENT - 1,
            CURRENT,
            CURRENT + 1
        )
    );
    assert!(!debug.contains(&seed_hex[..8]));
}

/// Two containers overlap during a rolling deploy and share the seed file;
/// both crossing a boundary must end up serving the same new window key,
/// so the second adopts the first's seed instead of minting its own.
// @internal
#[test]
fn two_stores_on_one_file_agree_after_both_advance() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_in(&dir);
    let mut old_container = WindowSeeds::load_or_create(&path, CURRENT).unwrap();
    let mut new_container = WindowSeeds::load_or_create(&path, CURRENT).unwrap();

    old_container.advance(&path, CURRENT + 1).unwrap();
    new_container.advance(&path, CURRENT + 1).unwrap();

    assert_eq!(seeds_of(&new_container), seeds_of(&old_container));
    assert_eq!(
        seeds_of(&WindowSeeds::load_or_create(&path, CURRENT + 1).unwrap()),
        seeds_of(&old_container)
    );
}

// A clock stepped back a window (an NTP correction) re-centres the store on
// the new window instead of keeping the old set (vauchi/private#552).
// @internal
#[test]
fn stepping_back_a_window_re_centres_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seeds.bin");
    let mut seeds = WindowSeeds::load_or_create(&path, 100).unwrap();
    assert_eq!(seeds.windows(), [99, 100, 101]);

    assert!(seeds.advance(&path, 99).unwrap());

    assert_eq!(seeds.windows(), [98, 99, 100]);
}
