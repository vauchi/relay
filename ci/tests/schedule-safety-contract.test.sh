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
        in_job && $0 != job ":" && /^[^[:space:]#]/ { exit }
        in_job { print }
    ' "$ci_config"
}

require_schedule_guard() {
    job=$1
    block=$(job_block "$job")
    schedule_line=$(printf '%s\n' "$block" |
        grep -n 'CI_PIPELINE_SOURCE == "schedule"' |
        head -1 | cut -d: -f1 || true)
    default_line=$(printf '%s\n' "$block" |
        grep -n 'CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH' |
        head -1 | cut -d: -f1 || true)

    if [ -n "$schedule_line" ] &&
        [ -n "$default_line" ] &&
        [ "$schedule_line" -lt "$default_line" ] &&
        printf '%s\n' "$block" |
        sed -n "${schedule_line},$((schedule_line + 1))p" |
        grep -q 'when: never'; then
        echo "PASS: $job excludes schedules before the default branch"
    else
        echo "FAIL: $job must exclude schedules before the default branch" >&2
        failures=$((failures + 1))
    fi
}

for job in \
    auto-tag:version \
    publish:package:relay \
    deploy:trigger \
    pages \
    github-mirror
do
    require_schedule_guard "$job"
done

docker_job=$(job_block build:docker)
if printf '%s\n' "$docker_job" |
    grep -q 'CI_PIPELINE_SOURCE" != "schedule"'; then
    echo "PASS: scheduled image builds cannot advance :latest"
else
    echo "FAIL: scheduled image builds must not advance :latest" >&2
    failures=$((failures + 1))
fi

[ "$failures" -eq 0 ]
