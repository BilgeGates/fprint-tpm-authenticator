#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Starts a private bus and points the "system bus" at it. Real fprintd is never used.
set -euo pipefail
test_binary=$1
exec dbus-run-session -- bash -c '
    export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" FPTA_PRIVATE_BUS=1
    unset DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR
    exec "$0"' "$test_binary"
