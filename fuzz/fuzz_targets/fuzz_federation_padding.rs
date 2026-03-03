// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for federation padding removal and bucket validation.
//!
//! Tests `unpad()` and `is_valid_bucket_size()` with arbitrary byte input
//! to find panics in the 4-byte BE length prefix parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::padding::{is_valid_bucket_size, unpad};

fuzz_target!(|data: &[u8]| {
    let _ = unpad(data);
    let _ = is_valid_bucket_size(data.len());
});
