// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for federation URL validation (SSRF prevention).
//!
//! Tests `validate_federation_url()` with arbitrary string input to find
//! panics in URL/IP parsing and private-range detection.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::url_validation::validate_federation_url;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate_federation_url(s);
    }
});
