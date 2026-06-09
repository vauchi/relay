// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Consolidated integration test binary for vauchi-relay.

#[allow(dead_code)]
mod common;
mod config_tests;
mod contract_protocol_tests;
mod escrow_store_tests;
mod exchange_adversarial_tests;
mod exchange_broker_tests;
mod federation_offload_core_tests;
mod http_api_exchange_tests;
mod http_api_guardian_tests;
mod http_api_ohttp_tests;
mod http_api_recovery_tests;
mod http_api_tests;
mod noise_integration_test;
mod rate_limit_ux;
mod relay_integration_test;
mod relay_load_test;
mod security_auth_tests;
mod security_resource_tests;
mod version_policy_tests;
