#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
swtpm=$1 test_binary=$2 daemon=$3
work=$(mktemp -d "${TMPDIR:-/tmp}/fpta-e2e.XXXXXX")
mkdir "$work/tpm"
"$swtpm" socket --tpm2 --tpmstate dir="$work/tpm" \
    --server type=unixio,path="$work/s" --ctrl type=unixio,path="$work/s.ctrl" \
    --flags not-need-init,startup-clear &
tpm_pid=$!
trap 'kill "$tpm_pid" 2>/dev/null || true; wait "$tpm_pid" 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 100); do [[ -S "$work/s" && -S "$work/s.ctrl" ]] && break; sleep 0.05; done
"$test_binary" "$daemon" "$work/state" "swtpm:path=$work/s"
