// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fuzz target for Noise NK handshake processing.
//!
//! Tests `NoiseResponder::process_handshake()` with arbitrary byte input
//! to find panics in the snow handshake state machine. A fresh relay
//! keypair is generated for each iteration.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::noise_transport::NoiseResponder;

fuzz_target!(|data: &[u8]| {
    let keypair = generate_relay_keypair();
    if let Ok(responder) = NoiseResponder::new(&keypair.private) {
        let _ = responder.process_handshake(data);
    }
});
