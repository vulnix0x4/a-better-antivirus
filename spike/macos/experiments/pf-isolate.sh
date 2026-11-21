#!/bin/bash
# Can the whole Mac be cut off with pf while a root daemon's alerts still get
# out? And can one *user's* traffic be cut (pf cannot match a process)?
#
# Usage: sudo experiments/pf-isolate.sh <uid of an ordinary user> [seconds]
#
# It loads rules into its own anchor under Apple's "com.apple/*" anchor point
# (so the main ruleset is not touched), holds them for a few seconds, and
# always removes them and gives back its pf enable token on exit.
set -u
U=${1:?uid of an ordinary user}
HOLD=${2:-8}
ANCHOR="com.apple/250.aba-spike"
ALERT_HOST=ntfy.sh          # stands in for the user's alert server
OTHER_HOST=example.com
TOKEN=""
cleanup() {
	pfctl -a "$ANCHOR" -F all 2>/dev/null
	[ -n "$TOKEN" ] && pfctl -X "$TOKEN" 2>/dev/null
	echo "[cleanup] anchor flushed, enable token released; pf is now: $(pfctl -s info 2>/dev/null | grep -m1 Status | awk '{print $2}')"
}
trap cleanup EXIT INT TERM

asuser() { sudo -u "#$U" "$@"; }
try() { # who host -> prints OK/blocked
	who=$1; host=$2; ip=$3
	if [ "$who" = root ]; then
		curl -s -o /dev/null -m 4 --resolve "$host:443:$ip" "https://$host/" && echo OK || echo blocked
	else
		asuser curl -s -o /dev/null -m 4 --resolve "$host:443:$ip" "https://$host/" && echo OK || echo blocked
	fi
}
ALERT_IP=$(dig +short A "$ALERT_HOST" | grep -E '^[0-9.]+$' | head -1)
OTHER_IP=$(dig +short A "$OTHER_HOST" | grep -E '^[0-9.]+$' | head -1)
echo "alert server $ALERT_HOST = $ALERT_IP (remembered while online); other host $OTHER_HOST = $OTHER_IP"
echo "pf before: $(pfctl -s info 2>/dev/null | grep -m1 Status | awk '{print $2}')"
table() {
	echo "  user -> other host : $(try user "$OTHER_HOST" "$OTHER_IP")"
	echo "  user -> alert host : $(try user "$ALERT_HOST" "$ALERT_IP")"
	echo "  root -> other host : $(try root "$OTHER_HOST" "$OTHER_IP")"
	echo "  root -> alert host : $(try root "$ALERT_HOST" "$ALERT_IP")"
	echo "  user DNS lookup    : $(asuser dig +time=2 +tries=1 +short A apple.com @1.1.1.1 2>/dev/null | grep -qE '^[0-9.]+$' && echo OK || echo blocked)"
}
echo "### baseline"
table

TOKEN=$(pfctl -E 2>&1 | awk '/Token/ {print $NF}')
echo "pf enabled with token ${TOKEN:-<none>}"

echo
echo "### A. cut one user's internet (uid $U); root and the rest of the system keep theirs"
pfctl -a "$ANCHOR" -f - <<EOF
block drop out quick proto { tcp, udp } from any to ! 127.0.0.0/8 user $U
EOF
echo "load exit: $?"; pfctl -a "$ANCHOR" -s rules 2>/dev/null
table
pfctl -a "$ANCHOR" -F all 2>/dev/null

echo
echo "### B. isolate the whole Mac for $HOLD s; only root may reach the alert server"
T0=$(date +%s)
pfctl -a "$ANCHOR" -f - <<EOF
pass quick on lo0 all
pass out quick proto tcp from any to $ALERT_IP port 443 user root
block drop quick all
EOF
echo "load exit: $?"; pfctl -a "$ANCHOR" -s rules 2>/dev/null
table
echo "  root sends a real alert while isolated: $(curl -s -m 5 -o /dev/null -w '%{http_code}' --resolve "$ALERT_HOST:443:$ALERT_IP" -d "aba spike isolation test" "https://$ALERT_HOST/aba-spike-$(date +%s)$RANDOM")"
while [ $(( $(date +%s) - T0 )) -lt "$HOLD" ]; do sleep 1; done
pfctl -a "$ANCHOR" -F all 2>/dev/null
echo
echo "### after removing the rules"
table
