#!/usr/bin/env bash
# shellcheck disable=SC2319  # $? deliberately reports the preceding test
# SPDX-License-Identifier: GPL-3.0-or-later
# Checks the installed system against the threat model and attacks the running
# stack with hostile input. Needs no sudo (one optional step asks for it).
# Creates no credentials and touches no fingerprint.
set -uo pipefail
log="$HOME/fpta-security-check.log"

main() {
    local results=() failed=0 dev="" node pid state
    report() {
        if (( $1 == 0 )); then results+=("✅ $2"); else results+=("❌ $2"); failed=1; fi
    }

    [[ $(stat -c '%U %a' /dev/uhid) == "root 600" ]]
    report $? "/dev/uhid is root-only (no user can create input devices)"

    for node in /sys/class/hidraw/hidraw*; do
        grep -q '^HID_NAME=fpta ' "$node/device/uevent" 2>/dev/null && dev="/dev/${node##*/}"
    done
    if [[ -z $dev ]]; then
        report 1 "virtual security key not found: start fptad first"
    else
        (( (8#$(stat -c '%a' "$dev") & 7) == 0 ))
        report $? "$dev is not accessible to other users"
        ! getfacl -p "$dev" 2>/dev/null | grep -E '^user:[^:]+:' | grep -v "^user:$USER:" | grep -q .
        report $? "$dev ACL grants only you"
        grep -q '^HID_ID=0006:00000000:00000000$' "/sys/class/hidraw/${dev##*/}/device/uevent"
        report $? "device is on the virtual bus and claims no USB ID"
    fi

    state=${XDG_DATA_HOME:-$HOME/.local/share}/fpta
    [[ $(stat -c '%U %a' "$state" 2>/dev/null) == "$USER 700" ]]
    report $? "state directory is private (0700)"
    ! find "$state" -type f -perm /077 2>/dev/null | grep -q .
    report $? "no state file is readable by others"

    local running
    running=$(systemctl show -p ExecMainStartTimestampMonotonic --value fpta-broker.service)
    [[ -z $running || $running == 0 ||
       $(stat -c %Y /usr/lib/fpta/fpta-broker) -le $(( $(date +%s) - ($(cut -d. -f1 /proc/uptime) - running / 1000000) )) ]]
    report $? "the running broker is the installed version (restart it after an upgrade)"

    pid=$(systemctl --user show -p MainPID --value fptad.service)
    if [[ -n $pid && $pid != 0 ]]; then
        ! cat "/proc/$pid/environ" >/dev/null 2>&1
        report $? "other programs of yours cannot read fptad memory (non-dumpable)"
        [[ $(awk '/^Max core file size/ {print $5}' "/proc/$pid/limits" 2>/dev/null) == 0 ]]
        report $? "fptad never writes core dumps"
    else
        report 1 "fptad is not running"
    fi

    local score
    score=$(systemd-analyze security --user fptad.service 2>/dev/null | sed -n 's/.*exposure level for fptad.service: \([0-9.]*\).*/\1/p')
    [[ -n $score ]] && awk -v s="$score" 'BEGIN { exit !(s < 2.0) }'
    report $? "fptad sandbox exposure below 2.0 (got ${score:-unknown})"
    score=$(systemd-analyze security fpta-broker.service 2>/dev/null | sed -n 's/.*exposure level for fpta-broker.service: \([0-9.]*\).*/\1/p')
    [[ -n $score ]] && awk -v s="$score" 'BEGIN { exit !(s < 2.0) }'
    report $? "broker sandbox exposure below 2.0 (got ${score:-unknown})"

    python3 -I - <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.settimeout(3)
s.connect("/run/fpta-broker.sock")
try:
    s.send(bytes(64))
    sys.exit(0 if s.recv(64) == b"" else 1)
except (ConnectionResetError, BrokenPipeError):
    sys.exit(0)
except socket.timeout:
    sys.exit(1)
PY
    report $? "a second program cannot take over the broker while fptad is connected"

    if [[ -n $dev ]]; then
        echo "--- sending 20000 hostile HID reports to $dev"
        python3 -I - "$dev" <<'PY'
import os, random, sys, time
fd = os.open(sys.argv[1], os.O_RDWR)
rng = random.Random(1)
def send(report):
    os.write(fd, b"\0" + report)
def recv_all():
    out = []
    while True:
        import select
        r, _, _ = select.select([fd], [], [], 0.02)
        if not r:
            return out
        out.append(os.read(fd, 64))
# allocate a channel
send(b"\xff\xff\xff\xff\x86\x00\x08" + b"12345678" + bytes(49))
time.sleep(0.2)
replies = recv_all()
cid = next(r[15:19] for r in replies if r[4] == 0x86 and r[7:15] == b"12345678")
for i in range(20000):
    kind = rng.randrange(6)
    if kind == 0:   # garbage on random channels
        report = bytes(rng.randrange(256) for _ in range(64))
    elif kind == 1: # huge declared length, never completed
        report = cid + b"\x90\xff\xff" + bytes(57)
    elif kind == 2: # continuation out of order
        report = cid + bytes([rng.randrange(128)]) + bytes(59)
    elif kind == 3: # random CBOR body for getInfo/makeCredential/getAssertion/reset
        body = bytes([rng.choice([1, 2, 4, 7, 8, 0x40])]) + bytes(rng.randrange(256) for _ in range(40))
        report = cid + b"\x90" + len(body).to_bytes(2, "big") + body + bytes(57 - len(body))
    elif kind == 4: # unknown commands
        report = cid + bytes([0x80 | rng.randrange(128), 0, 1]) + bytes(57)
    else:           # INIT storms
        report = b"\xff\xff\xff\xff\x86\x00\x08" + os.urandom(8) + bytes(49)
    send(report)
    if i % 200 == 0:
        recv_all()
recv_all()
PY
        report $? "hostile reports sent without breaking the device node"
        sleep 1
        fido2-token -I "$dev" | grep -q FIDO_2_0
        report $? "authenticator still answers normally afterwards"
        systemctl --user is-active --quiet fptad.service
        report $? "fptad survived (no crash or restart)"
        [[ $(systemctl --user show -p NRestarts --value fptad.service) == 0 ]]
        report $? "fptad restart counter is still 0"
    fi

    echo
    read -r -p "Optional: test that ANOTHER user is refused by the broker (uses sudo -u nobody). Run it? [y/N] " answer </dev/tty
    if [[ $answer == [yY] ]]; then
        sudo -u nobody python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.settimeout(3)
s.connect("/run/fpta-broker.sock")
try:
    sys.exit(0 if s.recv(64) == b"" else 1)
except ConnectionResetError:
    sys.exit(0)
except socket.timeout:
    sys.exit(1)'
        report $? "another user is refused by the broker"
    fi

    echo
    echo "===== RESULT ====="
    printf '%s\n' "${results[@]}"
    return "$failed"
}

main 2>&1 | tee "$log"
exit "${PIPESTATUS[0]}"
