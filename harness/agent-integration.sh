#!/bin/sh
# Phase 2 agent integration test: drives plait-agent with apply-file against a
# real kernel. Runs inside a privileged Linux container (see run-in-docker.sh);
# lib.sh describes the topology.
set -eu
umask 077

. "$(dirname "$0")/lib.sh"
apk add -q socat tcpdump iputils-ping >/dev/null # iputils for ping -M do

# --- controller state (plaitctl local administration) ---
cd "$WORK"
"$BIN/plaitctl" init-key psk.key 2>/dev/null
cat >plaitd.json <<EOF
{"database":"$WORK/plaitd.db","encryption_key_file":"$WORK/psk.key","client_pool":"10.0.0.0/24"}
EOF
export PLAIT_CONFIG=$WORK/plaitd.json

mkdir -p /etc/plait
cat >/etc/plait/agent.json <<EOF
{"site_id":"PLACEHOLDER","state_dir":"$WORK/agent","nft_path":"$(command -v nft)"}
EOF

# A foreign plait0 must never be taken over.
ip link add plait0 type wireguard
sed -i "s/PLACEHOLDER/probe/" /etc/plait/agent.json
GW_PUB=$("$BIN/plait-agent" init 2>/dev/null)

SITE_ID=$("$BIN/plaitctl" site add -name Lab -endpoint 192.0.2.1 -pubkey "$GW_PUB" -egress lan0 -subnet 10.15.0.0/24)
sed -i "s/\"site_id\":\"probe\"/\"site_id\":\"$SITE_ID\"/" /etc/plait/agent.json

wg genkey >client.key && chmod 600 client.key
"$BIN/plaitctl" device enroll phone -pubkey "$(wg pubkey <client.key)" >/dev/null
"$BIN/plaitctl" link add Lab phone >/dev/null

snapshot() { "$BIN/plaitctl" site snapshot Lab 2>/dev/null >snap.json; }
apply() { snapshot && "$BIN/plait-agent" apply-file snap.json 2>>agent.log; }

check_not "refuses to take over a foreign plait0" apply
check "foreign plait0 left untouched (no peers added)" sh -c '[ -z "$(wg show plait0 peers)" ]'
ip link del plait0

check "initial apply verifies" apply
check "plait0 owned and up" sh -c 'ip -d link show plait0 | grep -q "alias managed by plait-agent"'
check "return route installed with plait protocol" sh -c 'ip route show dev plait0 proto 77 | grep -q "^10.0.0.2 "'
check "nft table present" nft list table inet plait

# --- client profile, assembled locally ---
client_up client client.key phone

check "client reaches LAN host through masquerade" in_client ping -c 2 -W 2 10.15.0.10
check_not "client cannot reach gateway-local address" in_client ping -c 2 -W 1 10.15.0.1

# A modified client profile cannot reach unadvertised destinations.
in_client wg set wg0 peer "$GW_PUB" allowed-ips 10.15.0.0/24,10.16.0.0/24
in_client ip route add 10.16.0.0/24 dev wg0
check_not "edited client AllowedIPs cannot bypass gateway policy (unadvertised LAN)" in_client ping -c 2 -W 1 10.16.0.10
check_not "gateway did not adopt the client's edited AllowedIPs" sh -c 'wg show plait0 allowed-ips | grep -q 10.16.0.0'

# --- unchanged reconciliation leaves peers alone ---
ENDPOINT_BEFORE=$(wg show plait0 endpoints)
: >agent.log
check "repeat apply verifies" apply
check_not "repeat apply made no changes" grep -q "msg=reconciled" agent.log
check "learned client endpoint preserved" sh -c "[ \"\$(wg show plait0 endpoints)\" = \"$ENDPOINT_BEFORE\" ]"

# --- drift repair ---
ip route del 10.0.0.2/32 dev plait0
check_not "removing the return route breaks traffic despite the handshake" in_client ping -c 2 -W 1 10.15.0.10
check "drift apply repairs the route" apply
check "traffic recovers after route repair" in_client ping -c 2 -W 2 10.15.0.10

nft delete table inet plait
check "drift apply recreates the firewall" apply
check "traffic recovers after firewall repair" in_client ping -c 2 -W 2 10.15.0.10

nft add rule inet plait forward accept
check "drift apply removes a foreign rule in the plait table" apply
check "plait forward chain has only plait rules" sh -c '[ "$(nft -j list chain inet plait forward | grep -o "\"comment\"" | wc -l)" = "$(nft -j list chain inet plait forward | grep -o "\"rule\"" | wc -l)" ]'

# --- gateway-generated ICMP errors ---
# plait0 is unnumbered. The gateway's other interfaces (the container's eth0,
# wan0, wan2) come before lan0, so without a preferred source on the return
# route the kernel sends errors from an address outside the site's prefixes,
# which the client's WireGuard drops (SPEC 2.3, Phase 0).
# icmp_reaches_client <ping args>: an ICMP error from 10.15.0.1 arrives on wg0.
icmp_reaches_client() {
	: >icmp.cap
	in_client timeout 4 tcpdump -nli wg0 -c1 'icmp[0] == 3 or icmp[0] == 11' >icmp.cap 2>/dev/null &
	sleep 1
	in_client ping -c 1 -W 1 "$@" 10.15.0.10 || true
	wait $! || true
	grep -q ' IP 10.15.0.1 > 10.0.0.2: ICMP' icmp.cap
}
check "return route prefers the gateway's LAN address" sh -c 'ip route show dev plait0 proto 77 | grep -q "^10.0.0.2 .*src 10.15.0.1"'
check "client receives TTL exceeded from the gateway" icmp_reaches_client -t 1
ip link set lan0 mtu 1280
check "client receives Fragmentation Needed from the gateway" icmp_reaches_client -M do -s 1300
ip link set lan0 mtu 1500
ip route replace 10.0.0.2/32 dev plait0 proto 77 scope link   # drop the preferred source
check_not "without the preferred source, ICMP errors are dropped by the client" icmp_reaches_client -t 1
check "drift apply restores the preferred source" apply
check "ICMP errors reach the client again" icmp_reaches_client -t 1

# --- adding a peer does not interrupt an existing flow ---
wg genkey >client2.key && chmod 600 client2.key
"$BIN/plaitctl" device enroll laptop -pubkey "$(wg pubkey <client2.key)" >/dev/null
"$BIN/plaitctl" link add Lab laptop >/dev/null
in_client ping -c 30 -i 0.1 -W 1 10.15.0.10 >ping.log 2>&1 &
PING=$!
sleep 1
check "apply with an added peer verifies" apply
wait $PING || true
check "existing flow saw no loss while a peer was added" grep -q " 0% packet loss" ping.log
check "existing peer endpoint unchanged" sh -c "wg show plait0 endpoints | grep -q \"$(echo "$ENDPOINT_BEFORE" | cut -f2)\""

client_up client2 client2.key laptop 192.0.3.1:51111
check "second client reaches LAN" in_client2 ping -c 2 -W 2 10.15.0.10
in_client2 ip route add 10.0.0.0/24 dev wg0
ip netns exec client2 wg set wg0 peer "$GW_PUB" allowed-ips 10.15.0.0/24,10.0.0.0/24
check_not "client-to-client forwarding denied" in_client2 ping -c 2 -W 1 10.0.0.2

# --- gateway access from the tunnel ---
for port in 2222 2223; do socat TCP-LISTEN:$port,fork,reuseaddr SYSTEM:true 2>/dev/null & done
reach() { in_client socat -T 2 /dev/null "TCP:10.15.0.1:$1,connect-timeout=2"; }
check_not "gateway TCP port closed to clients by default" reach 2222
"$BIN/plaitctl" site update Lab -gateway-tcp-ports 2222
check "apply with gateway access verifies" apply
check "client reaches the allowed gateway port" reach 2222
check_not "client cannot reach other gateway ports" reach 2223
check_not "gateway still unreachable by ping" in_client ping -c 2 -W 1 10.15.0.1
"$BIN/plaitctl" site update Lab -gateway-tcp-ports ""
check "apply without gateway access verifies" apply
check_not "gateway port closed again" reach 2222

# --- host-managed nftables: a ruleset that flushes everything on reload ---
mkdir -p /etc/nftables/conf.d
host_ruleset() { # $1: 1 to integrate Plait (plait* forwarding, its UDP port)
	plait_fwd='' port=''
	[ "$1" = 1 ] && plait_fwd='iifname "plait*" accept
		oifname "plait*" accept' && port=', 51111'
	cat >host.nft <<EOF
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
		ip protocol icmp accept
		udp dport { 123$port } accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		iifname "wg*" accept
		$plait_fwd
	}
}
include "/etc/nftables/conf.d/*.nft"
EOF
	nft -f host.nft
}
check "configure the include file" "$BIN/plait-agent" configure -nft-include /etc/nftables/conf.d/plait.nft
check "apply writes the include file" apply
check "include file holds the plait table" grep -q "^table inet plait {" /etc/nftables/conf.d/plait.nft
check "host reload (flush ruleset + include) succeeds" host_ruleset 1
check "plait table survives the host reload" nft list table inet plait
check "no drift right after the host reload" sh -c "'$BIN/plait-agent' status 2>/dev/null | grep -q '\"drift\": \[\]'"
check "client reaches LAN through the host ruleset" in_client ping -c 2 -W 2 10.15.0.10
check_not "Plait still denies client-to-client under the host ruleset" in_client2 ping -c 2 -W 1 10.0.0.2
: >agent.log
host_ruleset 0
apply || true
check "warns: host forward chain lacks plait*" grep -q 'forward chain inet filter forward drops by default and no rule clearly accepts traffic from plait0' agent.log
check "warns: host input chain lacks the WireGuard port" grep -q 'input chain inet filter input drops by default and no rule clearly accepts UDP port 51111' agent.log
host_ruleset 1
: >agent.log
check "apply under the integrated host ruleset verifies" apply
check_not "no firewall warnings once integrated" grep -q 'no rule clearly accepts' agent.log
check "client reaches LAN again" in_client ping -c 2 -W 2 10.15.0.10

# --- revocation ---
"$BIN/plaitctl" device disable phone
check "revocation apply verifies" apply
check_not "revoked peer removed from plait0" sh -c "wg show plait0 peers | grep -q \"$(wg pubkey <client.key)\""
check_not "revoked device route removed" sh -c 'ip route show dev plait0 | grep -q "^10.0.0.2 "'
check_not "revoked client can no longer reach LAN" in_client ping -c 2 -W 1 10.15.0.10
check "other client unaffected by revocation" in_client2 ping -c 2 -W 2 10.15.0.10

# --- revision regression and corruption ---
cp snap.json newest.json
sed 's/"revision":[0-9]*/"revision":1/' newest.json >old.json
check_not "older revision rejected" "$BIN/plait-agent" apply-file old.json
printf 'garbage' >>"$WORK/agent/desired.json"
check "corrupt cache is detected, not used" sh -c "'$BIN/plait-agent' status 2>/dev/null | grep -q 'no valid cached desired state'"
check "a valid snapshot replaces the corrupt cache" "$BIN/plait-agent" apply-file newest.json
check "status reports no drift" sh -c "'$BIN/plait-agent' status 2>/dev/null | grep -q '\"drift\": \[\]'"

# --- site drain ---
"$BIN/plaitctl" site disable Lab
check "drain apply verifies" apply
check "drained site has no peers" sh -c '[ -z "$(wg show plait0 peers)" ]'

# --- uninstall ---
check "uninstall succeeds" "$BIN/plait-agent" uninstall
check_not "plait0 removed" ip link show plait0
check_not "nft table removed" nft list table inet plait
check_not "include file removed" test -e /etc/nftables/conf.d/plait.nft

DONE=1
echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "--- agent log ---"
  cat agent.log
  exit 1
fi
