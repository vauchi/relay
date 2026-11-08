// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The relay's errors reach operators only through logs (clients get a
//! generic answer, DC-05), so a log line is all an operator has: each error
//! must say which failure it was and carry its detail. Nightly mutation
//! testing found every one of these messages replaceable by an empty
//! string with no test noticing (vauchi/private#1179).

use std::collections::HashSet;
use vauchi_relay::content_proxy::ContentProxyError;
use vauchi_relay::recovery_proof_header::{RECOVERY_PROOF_VERSION, RecoveryProofHeader};
use vauchi_relay::storage_error::StorageWriteError;

// @internal
#[test]
fn each_content_proxy_failure_has_its_own_message() {
    let all = [
        ContentProxyError::NotAContentPath,
        ContentProxyError::InvalidOrigin,
        ContentProxyError::Unavailable,
        ContentProxyError::TooLarge,
    ];
    let messages: HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(
        messages.len(),
        all.len(),
        "messages must differ: {messages:?}"
    );
    assert!(messages.iter().all(|m| !m.is_empty()), "{messages:?}");
}

// @internal
#[test]
fn a_short_proof_says_how_long_the_header_is() {
    let err = RecoveryProofHeader::parse(&[RECOVERY_PROOF_VERSION]).unwrap_err();
    assert!(err.to_string().contains("33"), "{err}");
}

// @internal
#[test]
fn an_unsupported_version_names_both_versions() {
    let mut proof = vec![RECOVERY_PROOF_VERSION.wrapping_add(1)];
    proof.extend_from_slice(&[0; 32]);
    let err = RecoveryProofHeader::parse(&proof).unwrap_err().to_string();
    assert!(
        err.contains(&RECOVERY_PROOF_VERSION.wrapping_add(1).to_string()),
        "{err}"
    );
    assert!(err.contains(&RECOVERY_PROOF_VERSION.to_string()), "{err}");
}

// @internal
#[test]
fn a_refused_write_keeps_the_databases_reason() {
    let err = StorageWriteError::from(rusqlite::Error::InvalidQuery);
    let reason = rusqlite::Error::InvalidQuery.to_string();
    assert!(err.to_string().contains(&reason), "{err} lacks {reason}");
}
