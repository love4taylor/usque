#!/bin/sh
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG="${USQUE_CONFIG:-$BASE/config.json}"
NFT_TABLE="${USQUE_TPROXY_NFT_TABLE:-usque_tproxy}"
ROUTE_TABLE="${USQUE_TPROXY_TABLE:-100}"
MARK="${USQUE_TPROXY_MARK:-0x1/0x1}"
RULE_PRIORITY="${USQUE_TPROXY_RULE_PRIORITY:-100}"
PORT="${USQUE_TPROXY_PORT:-12345}"
BIND="${USQUE_TPROXY_BIND:-127.0.0.1}"
BIND_V6="${USQUE_TPROXY_BIND_V6:-}"
STATE="${USQUE_TPROXY_STATE:-/run/usque-tproxy.state}"
LOCK="${USQUE_TPROXY_LOCK:-/run/usque-tproxy.lock}"
IP="${USQUE_IP:-/usr/sbin/ip}"
NFT="${USQUE_NFT:-/usr/bin/nft}"
SS="${USQUE_SS:-/usr/bin/ss}"
FIREWALL_CMD="${USQUE_FIREWALL_CMD:-/usr/bin/firewall-cmd}"

fail() {
    echo "$*" >&2
    exit 1
}

valid_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
}

valid_mark() {
    case "$1" in
        0x*)
            value=${1#0x}
            case "$value" in
                ''|*[!0-9a-fA-F]*) return 1 ;;
            esac
            ;;
        ''|*[!0-9]*) return 1 ;;
    esac
}

valid_ipv4() {
    case "$1" in
        ''|*[!0-9.]*) return 1 ;;
    esac
}

valid_ipv6() {
    case "$1" in
        ''|*[!0-9a-fA-F:]*) return 1 ;;
    esac
}

check_firewalld_rpfilter() {
    [ "${USQUE_TPROXY_CHECK_FIREWALLD:-1}" = 1 ] || return 0
    [ -n "$BIND_V6" ] || return 0
    [ -x "$FIREWALL_CMD" ] || return 0
    "$FIREWALL_CMD" --state 2>/dev/null | grep -qx running || return 0

    if "$NFT" list chain inet firewalld filter_PREROUTING 2>/dev/null \
        | grep -Eq 'meta nfproto ipv6 fib saddr .* check missing drop'; then
        fail "firewalld IPv6_rpfilter blocks marked TPROXY packets; set IPv6_rpfilter=no in /etc/firewalld/firewalld.conf, restart firewalld, then start usque-tproxy (or set USQUE_TPROXY_CHECK_FIREWALLD=0 to override)"
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    fail "tproxy nftables setup must run as root"
fi
check_firewalld_rpfilter
if [ ! -r "$CONFIG" ]; then
    fail "usque config not found: $CONFIG"
fi
if [ ! -x "$NFT" ]; then
    fail "nft not found: $NFT"
fi
case "$NFT_TABLE" in
    ''|*[!a-zA-Z0-9_]*) fail "invalid nftables table name: $NFT_TABLE" ;;
esac
valid_number "$ROUTE_TABLE" || fail "invalid route table: $ROUTE_TABLE"
valid_number "$RULE_PRIORITY" || fail "invalid rule priority: $RULE_PRIORITY"
valid_number "$PORT" || fail "invalid TPROXY port: $PORT"
valid_ipv4 "$BIND" || fail "invalid IPv4 TPROXY bind address: $BIND"
[ -z "$BIND_V6" ] || valid_ipv6 "$BIND_V6" || fail "invalid IPv6 TPROXY bind address: $BIND_V6"

MARK_VALUE=${MARK%%/*}
MARK_MASK=${MARK#*/}
[ "$MARK_MASK" = "$MARK" ] && MARK_MASK=0xffffffff
valid_mark "$MARK_VALUE" || fail "invalid TPROXY mark: $MARK"
valid_mark "$MARK_MASK" || fail "invalid TPROXY mark mask: $MARK"

if [ "${USQUE_TPROXY_SKIP_LISTENER_CHECK:-0}" != 1 ]; then
    if [ ! -x "$SS" ] || ! "$SS" -H -ltn 2>/dev/null | grep -Eq ":${PORT}[[:space:]]" || ! "$SS" -H -lun 2>/dev/null | grep -Eq ":${PORT}[[:space:]]"; then
        fail "TPROXY listeners are not ready on port $PORT; refusing to change nftables"
    fi
fi

json_field() {
    key=$1
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$CONFIG" | head -n 1
}

endpoint4=$(json_field endpoint_v4)
endpoint6=$(json_field endpoint_v6)
if [ "${USQUE_HTTP2:-0}" = 1 ]; then
    h2_endpoint4=$(json_field endpoint_h2_v4)
    h2_endpoint6=$(json_field endpoint_h2_v6)
    [ -n "$h2_endpoint4" ] && endpoint4=$h2_endpoint4
    [ -n "$h2_endpoint6" ] && endpoint6=$h2_endpoint6
fi

case "$endpoint4" in
    ''|*[!0-9.]*) endpoint4='' ;;
esac
case "$endpoint6" in
    ''|*[!0-9a-fA-F:]*) endpoint6='' ;;
esac
if [ -z "$endpoint4" ] && [ -z "$endpoint6" ]; then
    fail "no usable Cloudflare endpoint found in $CONFIG"
fi

exec 9>"$LOCK"
flock -x 9

RULES_FILE=$(mktemp /run/usque-tproxy-nft.XXXXXX)
success=0
applied=0
state_written=0

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -f "$RULES_FILE"
    if [ "$success" -ne 1 ] && [ "$applied" -eq 1 ]; then
        while "$IP" -4 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
        "$IP" -4 route del local 0.0.0.0/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
        if [ -n "$BIND_V6" ]; then
            while "$IP" -6 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
            "$IP" -6 route del local ::/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
            "$IP" -6 route del ::/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
        fi
        "$NFT" delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
    fi
    if [ "$success" -ne 1 ] && [ "$state_written" -eq 1 ]; then
        rm -f "$STATE"
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

{
    cat <<EOF
destroy table inet $NFT_TABLE
table inet $NFT_TABLE {
    chain prerouting {
        type filter hook prerouting priority -150; policy accept;
EOF
    cat <<EOF
        meta mark & $MARK_MASK == 0 fib daddr type local return
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return
EOF
    [ -n "$endpoint4" ] && printf '        ip daddr %s return\n' "$endpoint4"
    if [ -n "$BIND_V6" ]; then
        cat <<EOF
        ip6 daddr { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 } return
EOF
        [ -n "$endpoint6" ] && printf '        ip6 daddr %s return\n' "$endpoint6"
    fi
    cat <<EOF
        meta nfproto ipv4 meta l4proto tcp tproxy ip to $BIND:$PORT meta mark set $MARK_VALUE
        meta nfproto ipv4 meta l4proto udp tproxy ip to $BIND:$PORT meta mark set $MARK_VALUE
EOF
    if [ -n "$BIND_V6" ]; then
        cat <<EOF
        meta nfproto ipv6 meta l4proto tcp tproxy ip6 to [$BIND_V6]:$PORT meta mark set $MARK_VALUE
        meta nfproto ipv6 meta l4proto udp tproxy ip6 to [$BIND_V6]:$PORT meta mark set $MARK_VALUE
EOF
    fi
    cat <<EOF
    }

    chain output {
        type route hook output priority -150; policy accept;
        ct direction reply return
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return
EOF
    [ -n "$endpoint4" ] && printf '        ip daddr %s return\n' "$endpoint4"
    if [ -n "$BIND_V6" ]; then
        cat <<EOF
        ip6 daddr { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 } return
EOF
        [ -n "$endpoint6" ] && printf '        ip6 daddr %s return\n' "$endpoint6"
    fi
    cat <<EOF
        meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set $MARK_VALUE
EOF
    if [ -n "$BIND_V6" ]; then
        cat <<EOF
        meta nfproto ipv6 meta l4proto { tcp, udp } meta mark set $MARK_VALUE
EOF
    fi
    cat <<EOF
    }
}
EOF
} >"$RULES_FILE"

"$NFT" -c -f "$RULES_FILE"
"$NFT" -f "$RULES_FILE"
applied=1

while "$IP" -4 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
"$IP" -4 route replace local 0.0.0.0/0 dev lo table "$ROUTE_TABLE"
"$IP" -4 rule add pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE"
if [ -n "$BIND_V6" ]; then
    while "$IP" -6 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
    "$IP" -6 route replace local ::/0 dev lo table "$ROUTE_TABLE"
    "$IP" -6 rule add pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE"
fi
"$IP" route flush cache 2>/dev/null || true

umask 077
{
    printf 'NFT_TABLE=%s\n' "$NFT_TABLE"
    printf 'ROUTE_TABLE=%s\n' "$ROUTE_TABLE"
    printf 'MARK=%s\n' "$MARK"
    printf 'RULE_PRIORITY=%s\n' "$RULE_PRIORITY"
    printf 'IPV6_ENABLED=%s\n' "${BIND_V6:+1}"
} >"$STATE"
state_written=1

success=1
echo "TPROXY nftables rules enabled: table=$NFT_TABLE route_table=$ROUTE_TABLE mark=$MARK port=$PORT"
