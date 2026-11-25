#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Real hardware check: TPM, services, device, then one registration and one
# sign-in verified by libfido2. Creates a throwaway non-resident credential.
# No sudo, no system changes.
set -uo pipefail
log="$HOME/fpta-hw-check.log"

main() {
    local results=() failed=0 dev="" work
    work=$(mktemp -d)
    trap 'rm -rf "$work"' RETURN
    report() {
        if (( $1 == 0 )); then results+=("✅ $2"); else results+=("❌ $2"); failed=1; fi
    }
    skip() { results+=("⏭  $1 (not run: an earlier step failed)"); failed=1; }
    # Journal position, so that each step shows only its own reader events.
    mark() {
        journalctl --user-unit fptad -n 0 --show-cursor --no-pager 2>/dev/null |
            sed -n 's/^-- cursor: //p'
    }
    events() {
        sleep 1
        local range=(--since '-1min')
        [[ -n "$1" ]] && range=(--after-cursor "$1")
        journalctl --user-unit fptad "${range[@]}" -o short-precise --no-pager 2>/dev/null |
            grep 'fingerprint reader:'
    }
    show() {
        echo "--- reader events in this step:"
        if [[ -n "$1" ]]; then echo "$1"; else echo "(none found in the journal)"; fi
    }
    ask() {
        echo
        echo ">>> $1"
        read -r -p ">>> press Enter when ready " </dev/tty
    }

    id -nG | tr ' ' '\n' | grep -qx tss; report $? "this session is in the tss group"
    fptad --check; report $? "TPM is usable"
    fprintd-list "$USER" | grep -q -- '- #'; report $? "a fingerprint is enrolled"
    systemctl is-active --quiet fpta-broker.socket; report $? "broker socket is active"
    systemctl --user restart fptad.service; sleep 2
    systemctl --user is-active --quiet fptad.service; report $? "user service is running"

    for node in /sys/class/hidraw/hidraw*; do
        grep -q '^HID_NAME=fpta ' "$node/device/uevent" 2>/dev/null && dev="/dev/${node##*/}"
    done
    [[ -n "$dev" ]]; report $? "virtual security key exists ${dev}"
    if [[ -n "$dev" ]]; then
        [[ -r "$dev" && -w "$dev" ]]; report $? "your user can open $dev (what the browser needs)"
        fido2-token -I "$dev" | grep -q FIDO_2_0; report $? "device answers getInfo"

        { head -c 32 /dev/urandom | base64; echo fpta.test; echo hwcheck
          head -c 16 /dev/urandom | base64; } >"$work/cred.in"
        local at seen status registered=0 signed=0

        ask "STEP 1, REGISTER: use your ENROLLED finger. One touch, then lift it."
        at=$(mark)
        fido2-cred -M -i "$work/cred.in" -o "$work/cred.out" "$dev" es256
        status=$?
        show "$(events "$at")"
        report $status "registration with the enrolled finger"
        if (( status == 0 )); then
            fido2-cred -V -v -i "$work/cred.out" -o "$work/cred.pub" es256
            status=$?
            report $status "registration signature verifies, user-verified flag set"
            (( status == 0 )) && registered=1
        else
            skip "registration signature"
        fi

        if (( registered )); then
            { head -c 32 /dev/urandom | base64; echo fpta.test; head -n 1 "$work/cred.pub"; } \
                >"$work/assert.in"
            tail -n +2 "$work/cred.pub" >"$work/pub.pem"
            ask "STEP 2, SIGN IN: use your ENROLLED finger. One touch, then lift it."
            at=$(mark)
            fido2-assert -G -i "$work/assert.in" -o "$work/assert.out" "$dev"
            status=$?
            show "$(events "$at")"
            report $status "sign-in with the enrolled finger"
            if (( status == 0 )); then
                fido2-assert -V -v -i "$work/assert.out" "$work/pub.pem" es256
                status=$?
                report $status "sign-in signature verifies"
                (( status == 0 )) && signed=1
            else
                skip "sign-in signature"
            fi
        else
            skip "sign-in"
        fi

        if (( signed )); then
            ask "STEP 3, WRONG FINGER: use ONLY a NOT enrolled finger, up to 3 touches,
>>> lifting it each time. NEVER the enrolled finger."
            at=$(mark)
            fido2-assert -G -i "$work/assert.in" -o "$work/wrong.out" "$dev" 2>"$work/wrong.err"
            status=$?
            command cat "$work/wrong.err"
            seen=$(events "$at")
            show "$seen"
            if (( status == 0 )); then
                report 1 "wrong finger is rejected (A SIGNATURE WAS ISSUED: see step 3 events)"
            elif grep -q FIDO_ERR_OPERATION_DENIED "$work/wrong.err" &&
                 grep -q 'verify-no-match' <<<"$seen" &&
                 ! grep -qE 'verify-match$' <<<"$seen"; then
                report 0 "wrong finger is rejected"
            else
                report 1 "wrong finger test is INCONCLUSIVE (no proven rejection)"
            fi
        else
            skip "wrong finger rejection"
        fi
    fi
    echo
    echo "===== RESULT ====="
    printf '%s\n' "${results[@]}"
    (( failed )) && echo "Service log: journalctl --user-unit fptad --since -5min"
    return "$failed"
}

main 2>&1 | tee "$log"
exit "${PIPESTATUS[0]}"
