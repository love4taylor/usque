#!/bin/sh
set -u

NFT_TABLE="${USQUE_TPROXY_NFT_TABLE:-usque_tproxy}"
ROUTE_TABLE="${USQUE_TPROXY_TABLE:-100}"
MARK="${USQUE_TPROXY_MARK:-0x1/0x1}"
RULE_PRIORITY="${USQUE_TPROXY_RULE_PRIORITY:-100}"
IPV6_ENABLED="${USQUE_TPROXY_IPV6_ENABLED:-${USQUE_TPROXY_BIND_V6:+1}}"
STATE="${USQUE_TPROXY_STATE:-/run/usque-tproxy.state}"
LOCK="${USQUE_TPROXY_LOCK:-/run/usque-tproxy.lock}"
IP="${USQUE_IP:-/usr/sbin/ip}"
NFT="${USQUE_NFT:-/usr/bin/nft}"

exec 9>"$LOCK"
flock -x 9

if [ -r "$STATE" ]; then
    . "$STATE"
fi

while "$IP" -4 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
if [ "$IPV6_ENABLED" = 1 ]; then
    while "$IP" -6 rule del pref "$RULE_PRIORITY" fwmark "$MARK" lookup "$ROUTE_TABLE" >/dev/null 2>&1; do :; done
fi

"$NFT" delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
"$IP" -4 route del local 0.0.0.0/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
if [ "$IPV6_ENABLED" = 1 ]; then
    "$IP" -6 route del local ::/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
    "$IP" -6 route del ::/0 dev lo table "$ROUTE_TABLE" >/dev/null 2>&1 || true
fi
"$IP" route flush cache 2>/dev/null || true
rm -f "$STATE"

echo "TPROXY nftables rules disabled: table=$NFT_TABLE route_table=$ROUTE_TABLE"
