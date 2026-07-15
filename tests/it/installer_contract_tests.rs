// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::{Command, Output};

fn run_installer_contract(command: &str, arguments: &[&str]) -> Output {
    Command::new("bash")
        .args(["-c", command, "installer-contract"])
        .args(arguments)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("bash must execute the installer contract")
}

// @internal
#[test]
fn test_installer_x86_64_uses_published_amd64_artifact_name() {
    let output = run_installer_contract("source deploy/install.sh; package_arch x86_64", &[]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "installer contract failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("installer output must be UTF-8"),
        "amd64\n"
    );
    assert_eq!(output.stderr, Vec::<u8>::new());
}

// @internal
#[test]
fn test_validate_release_ref_stable_tag_and_full_sha_succeed() {
    for release_ref in ["v1.2.3", "0123456789abcdef0123456789abcdef01234567"] {
        let output = run_installer_contract(
            "source deploy/install.sh; validate_release_ref \"$1\"",
            &[release_ref],
        );

        assert_eq!(
            output.status.code(),
            Some(0),
            "expected {release_ref:?} to be accepted: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert_eq!(output.stderr, Vec::<u8>::new());
    }
}

// @internal
#[test]
fn test_validate_release_ref_mutable_or_malformed_values_fail() {
    for release_ref in [
        "",
        "main",
        "test",
        "v1.2",
        "v1.2.3-rc.1",
        "v1.2.3/../../main",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "v1.2.3;touch /tmp/vauchi-installer-injection",
        "v1.2.3☃",
    ] {
        let output = run_installer_contract(
            "source deploy/install.sh; validate_release_ref \"$1\"",
            &[release_ref],
        );

        assert_eq!(
            output.status.code(),
            Some(1),
            "expected {release_ref:?} to be rejected"
        );
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert_eq!(output.stderr, Vec::<u8>::new());
    }
}
