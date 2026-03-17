// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property-based tests (CC-04, CC-14) for handler validation logic.

use super::*;

use proptest::prelude::*;

proptest! {
    /// Any 64-char hex string is a valid client ID.
    #[test]
    fn prop_valid_hex_64_accepted(s in "[0-9a-f]{64}") {
        prop_assert!(validate_client_id(&s));
    }

    /// Any string that is NOT exactly 64 hex chars is rejected.
    #[test]
    fn prop_wrong_length_rejected(len in 0usize..200) {
        prop_assume!(len != 64);
        let s: String = "a".repeat(len);
        prop_assert!(!validate_client_id(&s));
    }

    /// A 64-char string containing any non-hex character is rejected.
    #[test]
    fn prop_non_hex_char_rejected(
        pos in 0usize..64,
        bad_char in prop::char::range('g', 'z'),
    ) {
        let mut chars: Vec<char> = "a".repeat(64).chars().collect();
        chars[pos] = bad_char;
        let s: String = chars.into_iter().collect();
        prop_assert!(!validate_client_id(&s));
    }

    /// Arbitrary strings: validate_client_id returns true iff
    /// length == 64 and all chars are hex digits.
    #[test]
    fn prop_validate_matches_spec(s in "\\PC{0,128}") {
        let expected = s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
        prop_assert_eq!(validate_client_id(&s), expected);
    }

    /// Adversarial: unicode, null bytes, injection payloads all rejected.
    #[test]
    fn prop_adversarial_inputs_rejected(
        s in prop::string::string_regex("(.|\n){0,200}").unwrap()
    ) {
        // Only accept 64-char pure-hex strings
        let expected = s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
        prop_assert_eq!(validate_client_id(&s), expected);
    }
}
