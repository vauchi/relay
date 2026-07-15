// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::Command;

// @internal
#[test]
fn test_installer_x86_64_uses_published_amd64_artifact_name() {
    let output = Command::new("bash")
        .args(["-c", "source deploy/install.sh; package_arch x86_64"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("bash must execute the installer contract");

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
