// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for client ID validation.
//!
//! Tests `validate_client_id()` with arbitrary string input to find
//! panics in 64-char hex validation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::handler::validate_client_id;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate_client_id(s);
    }
});
