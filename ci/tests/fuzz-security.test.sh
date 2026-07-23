#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
PIPELINE="$ROOT/.gitlab-ci.yml"
FUZZ_ROOT="$ROOT/fuzz"
failed=0

fail() {
    echo "FAIL: $1" >&2
    failed=$((failed + 1))
}

job=$(awk '
    /^fuzz:nightly:/ { in_job = 1 }
    in_job && NR > 1 && /^[^ ]/ && !/^fuzz:nightly:/ { exit }
    in_job { print }
' "$PIPELINE")

printf '%s\n' "$job" | grep -q '^  allow_failure: false$' \
    || fail "nightly fuzz crashes do not block the scheduled pipeline"
printf '%s\n' "$job" | grep -q "cargo +nightly fuzz coverage \"\$t\"" \
    || fail "nightly fuzzing does not measure corpus coverage"
printf '%s\n' "$job" | grep -q "\"\$LLVM_COV\" report" \
    || fail "nightly fuzzing does not summarize coverage"
printf '%s\n' "$job" | grep -q 'fuzz/coverage/' \
    || fail "coverage data is not retained as a job artifact"

for target_file in "$FUZZ_ROOT"/fuzz_targets/*.rs; do
    target=$(basename "$target_file" .rs)
    printf '%s\n' "$job" | grep -qw "$target" \
        || fail "$target is absent from the nightly fuzz target list"
    has_seed=false
    for seed in "$FUZZ_ROOT/corpus/$target"/seed-*; do
        if [ -f "$seed" ]; then
            has_seed=true
            break
        fi
    done
    [ "$has_seed" = true ] || fail "$target has no curated seed corpus"
done

for configured_target in $(printf '%s\n' "$job" |
    sed -n '/TARGETS="/,/"/p' |
    grep -o 'fuzz_[a-z0-9_]*' |
    sort -u); do
    [ -f "$FUZZ_ROOT/fuzz_targets/$configured_target.rs" ] \
        || fail "$configured_target is configured but has no fuzz target"
done

[ "$failed" -eq 0 ] || exit 1
echo "PASS: relay fuzzing blocks crashes and retains measured seeded coverage"
