#!/bin/sh
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC_ROOT=$(CDPATH= cd -- "$BASE/../.." && pwd)
PREFIX=/usr/local/libexec/usque
CONFIG_DIR=/etc/usque
UNIT=/etc/systemd/system/usque-tproxy.service
DROPIN_DIR=/etc/systemd/system/usque-tproxy.service.d
GO_BIN="${USQUE_GO:-$(command -v go 2>/dev/null || true)}"
BUILD_DIR=
VERSION="${USQUE_VERSION:-dev}"
COMMIT="${USQUE_COMMIT:-$(git -C "$SRC_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf '%s' none)}"
BUILD_DATE="${USQUE_BUILD_DATE:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
LDFLAGS="-s -w -X github.com/Diniboy1123/usque/cmd.version=$VERSION -X github.com/Diniboy1123/usque/cmd.commit=$COMMIT -X github.com/Diniboy1123/usque/cmd.date=$BUILD_DATE"

if [ "$(id -u)" -ne 0 ]; then
    echo "run this installer as root (sudo $0)" >&2
    exit 1
fi

if [ -z "$GO_BIN" ] || [ ! -x "$GO_BIN" ]; then
    echo "Go compiler not found; install Go before running $0" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d /run/usque-tproxy-build.XXXXXX)
cleanup() {
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

echo "building usque from $SRC_ROOT"
(cd "$SRC_ROOT" && "$GO_BIN" build -trimpath -ldflags "$LDFLAGS" -o "$BUILD_DIR/usque" .)

install -d -m 0755 "$PREFIX" "$CONFIG_DIR"
install -d -m 0755 "$DROPIN_DIR"
install -m 0755 "$BUILD_DIR/usque" "$PREFIX/usque"
install -m 0755 "$BASE/run-tproxy.sh" "$PREFIX/run-tproxy.sh"
install -m 0755 "$BASE/tproxy-nftables-up.sh" "$PREFIX/tproxy-nftables-up.sh"
install -m 0755 "$BASE/tproxy-nftables-down.sh" "$PREFIX/tproxy-nftables-down.sh"
install -m 0644 "$BASE/usque-tproxy.service" "$UNIT"
install -m 0644 "$BASE/usque-tproxy-timeout.conf" "$DROPIN_DIR/99-timeout.conf"

if [ -e "$CONFIG_DIR/config.json" ]; then
    echo "keeping existing $CONFIG_DIR/config.json"
elif [ -r "$SRC_ROOT/config.json" ]; then
    install -m 0600 "$SRC_ROOT/config.json" "$CONFIG_DIR/config.json"
else
    echo "config missing: create $CONFIG_DIR/config.json before starting usque-tproxy.service" >&2
fi

systemctl daemon-reload
echo "installed usque-tproxy.service"
echo "start with: systemctl enable --now usque-tproxy.service"
