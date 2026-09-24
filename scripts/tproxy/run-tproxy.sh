#!/bin/sh
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG="${USQUE_CONFIG:-$BASE/config.json}"
BIND="${USQUE_TPROXY_BIND:-127.0.0.1}"
BIND_V6="${USQUE_TPROXY_BIND_V6:-}"
PORT="${USQUE_TPROXY_PORT:-12345}"
SS="${USQUE_SS:-/usr/bin/ss}"
READY_TIMEOUT="${USQUE_TPROXY_READY_TIMEOUT:-30}"

set -- --bind "$BIND" --port "$PORT" --always-reconnect "$@"
if [ -n "$BIND_V6" ]; then
    set -- --bind-v6 "$BIND_V6" "$@"
fi
if [ "${USQUE_HTTP2:-0}" = 1 ]; then
    set -- --http2 "$@"
fi
if [ "${USQUE_IPV6:-0}" = 1 ]; then
    set -- --ipv6 "$@"
fi
if [ "${USQUE_TPROXY_TCP_L4:-0}" = 1 ]; then
    set -- --tcp-l4 "$@"
fi

"$BASE/usque" --config "$CONFIG" tproxy "$@" &
child=$!
child_running=1
firewall_active=0

cleanup() {
    if [ "$firewall_active" -eq 1 ]; then
        "$BASE/tproxy-nftables-down.sh" >/dev/null 2>&1 || true
        firewall_active=0
    fi
    if [ "$child_running" -eq 1 ]; then
        kill -TERM "$child" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ready=0
elapsed=0
while [ "$elapsed" -lt "$READY_TIMEOUT" ]; do
    if ! kill -0 "$child" 2>/dev/null; then
        wait "$child" || true
        echo "usque tproxy exited before listeners became ready" >&2
        exit 1
    fi
    if "$SS" -H -ltn 2>/dev/null | grep -Eq ":${PORT}[[:space:]]" \
        && "$SS" -H -lun 2>/dev/null | grep -Eq ":${PORT}[[:space:]]"; then
        ready=1
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [ "$ready" -ne 1 ]; then
    echo "timed out waiting for TPROXY listeners on port $PORT" >&2
    exit 1
fi

firewall_active=1
if ! "$BASE/tproxy-nftables-up.sh"; then
    "$BASE/tproxy-nftables-down.sh" >/dev/null 2>&1 || true
    firewall_active=0
    echo "failed to enable TPROXY nftables rules" >&2
    exit 1
fi

if wait "$child"; then
    status=0
else
    status=$?
fi
child_running=0
exit "$status"
