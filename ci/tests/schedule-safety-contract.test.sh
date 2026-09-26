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

# Run build:docker's own tag-selection snippet once per pipeline source, so
# the test follows the behaviour rather than the spelling of the condition.
docker_job=$(job_block build:docker)
tag_selection=$(printf '%s\n' "$docker_job" |
    sed -n '/DESTS="--destination/,/^      fi$/p' |
    sed 's/^      //')

destinations_for() {
    CI_PIPELINE_SOURCE=$1 CI_COMMIT_BRANCH=main CI_DEFAULT_BRANCH=main \
        CI_REGISTRY_IMAGE=registry.example/vauchi/relay CI_COMMIT_SHA=abc123 \
        sh -c "$tag_selection
printf '%s' \"\$DESTS\""
}

if [ -z "$tag_selection" ]; then
    echo "FAIL: build:docker tag selection not found" >&2
    failures=$((failures + 1))
else
    for source in schedule pipeline trigger api; do
        case "$(destinations_for "$source")" in
            *:latest*)
                echo "FAIL: $source image builds must not advance :latest" >&2
                failures=$((failures + 1)) ;;
            *) echo "PASS: $source image builds cannot advance :latest" ;;
        esac
    done
    for source in push web; do
        case "$(destinations_for "$source")" in
            *:latest*) echo "PASS: $source image builds advance :latest" ;;
            *)
                echo "FAIL: $source image builds must advance :latest" >&2
                failures=$((failures + 1)) ;;
        esac
    done
fi

# A rebuild of unchanged, lock-pinned sources has nothing to deploy.
trigger_job=$(job_block deploy:trigger)
rebuild_line=$(printf '%s\n' "$trigger_job" |
    grep -n 'CI_PIPELINE_SOURCE == "pipeline"' | head -1 | cut -d: -f1 || true)
default_line=$(printf '%s\n' "$trigger_job" |
    grep -n 'CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH' | head -1 | cut -d: -f1 || true)
if [ -n "$rebuild_line" ] && [ -n "$default_line" ] &&
    [ "$rebuild_line" -lt "$default_line" ] &&
    printf '%s\n' "$trigger_job" |
    sed -n "${rebuild_line},$((rebuild_line + 1))p" |
    grep -q 'when: never'; then
    echo "PASS: deploy:trigger excludes upstream rebuilds before the default branch"
else
    echo "FAIL: deploy:trigger must exclude upstream rebuilds before the default branch" >&2
    failures=$((failures + 1))
fi

if printf '%s\n' "$trigger_job" |
    grep -q 'DEPLOY_IMAGE_DIGEST: \$DEPLOY_IMAGE_DIGEST'; then
    echo "PASS: deploy:trigger forwards the built image digest"
else
    echo "FAIL: deploy:trigger must forward the built image digest" >&2
    failures=$((failures + 1))
fi

[ "$failures" -eq 0 ]
