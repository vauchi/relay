// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for Noise V2 magic byte prefix detection.
//!
//! Tests V2_MAGIC prefix checking with arbitrary byte input to ensure
//! the guard never panics on any input. This mirrors the logic in
//! `handler::connection::perform_handshake` which rejects non-Noise connections.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::noise_transport::V2_MAGIC;

fuzz_target!(|data: &[u8]| {
    // Mirror the guard in perform_handshake: check magic prefix without panicking
    let _is_noise = data.len() >= V2_MAGIC.len() && data[..V2_MAGIC.len()] == V2_MAGIC;
});
