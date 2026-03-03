// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for Noise v2 handshake detection.
//!
//! Tests `is_noise_v2_handshake()` with arbitrary byte input to find
//! panics in magic byte and size checking. Trivial function but guards
//! the security-critical protocol upgrade path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::noise_transport::is_noise_v2_handshake;

fuzz_target!(|data: &[u8]| {
    let _ = is_noise_v2_handshake(data);
});
