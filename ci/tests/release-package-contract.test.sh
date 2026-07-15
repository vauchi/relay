#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

ci_config="${1:-.gitlab-ci.yml}"
failures=0

job_block() {
    awk -v job="$1" '
        $0 == job ":" { in_job = 1 }
        in_job && $0 != job ":" && /^[^[:space:]]/ { exit }
        in_job { print }
    ' "$ci_config"
}

build_job=$(job_block build:release)
install_job=$(job_block test:install)
publish_job=$(job_block publish:package:relay)

require_pattern() {
    description="$1"
    pattern="$2"
    content="$3"
    if printf '%s\n' "$content" | grep -Eq -- "$pattern"; then
        echo "PASS: $description"
    else
        echo "FAIL: $description" >&2
        failures=$((failures + 1))
    fi
}

require_pattern \
    "release package builds on the glibc 2.31 baseline" \
    'image: .*rust:1\.93\.1-bullseye' \
    "$build_job"
require_pattern \
    "release package build uses a container runner" \
    'tags: \[docker\]' \
    "$build_job"
require_pattern \
    "release package build uses the committed lockfile" \
    'cargo build --release --locked' \
    "$build_job"
require_pattern \
    "installer smoke test runs on the glibc 2.31 baseline" \
    'image: .*debian:bullseye-slim' \
    "$install_job"
require_pattern \
    "installer smoke test starts the installed artifact on loopback" \
    'RELAY_LISTEN_ADDR=127\.0\.0\.1:[0-9]+ /usr/local/bin/vauchi-relay' \
    "$install_job"
require_pattern \
    "installer smoke test verifies relay readiness" \
    'http://127\.0\.0\.1:[0-9]+/health' \
    "$install_job"
require_pattern \
    "installer smoke test consumes build:release" \
    'job: build:release' \
    "$install_job"
require_pattern \
    "package publication consumes build:release" \
    'job: build:release' \
    "$publish_job"

if [ "$failures" -ne 0 ]; then
    exit 1
fi
