// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for federation message decoding.
//!
//! Tests `decode_federation_message()` with arbitrary byte input to find
//! panics in padded binary frame parsing and JSON deserialization of
//! `FederationEnvelope`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::federation_protocol::decode_federation_message;

fuzz_target!(|data: &[u8]| {
    let _ = decode_federation_message(data);
});
