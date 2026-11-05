#!/bin/sh
# Phase 0 networking proof (SPEC §8): the parts that a Linux kernel in network
# namespaces can establish. Runs inside a privileged container (see
# run-in-docker.sh). Each gateway is its own namespace running plait-agent
# with apply-file, so its plait0, routes, nftables, and sysctls are separate.
#
#   client  100.64.0.2 --c0--+                     +--wan0 gw1 198.18.1.2   lan0 10.15.0.1 -- lan1 10.15.0.10
#   (10.0.0.2 on wg0)        |                     |   (mgmt0 192.168.99.1 created first)
#                            +-- inet (router) ----+
#   client2 100.64.1.2 --c1--+  g1/g2 underlay MTU +--wan0 gw2 198.18.2.2   lan0 10.25.0.1 -- lan2 10.25.0.10
#   (10.0.0.3 on wg0)                                  (lan0 created first)
#
# LAN hosts have no route to the client pool; replies only work through each
# gateway's masquerade.
set -eu
umask 077

BIN=${BIN:-/plait/bin}
WORK=$(mktemp -d)
PASS=0
FAIL=0
trap '[ "${DONE:-}" = 1 ] || { echo "HARNESS ABORTED (passed: $PASS failed: $FAIL)"; exit 1; }' EXIT

pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
check() { desc=$1; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
check_not() { desc=$1; shift; if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi; }
note() { echo "NOTE: $*"; }
# recovers <ns> <dst> <max-seconds>: wait for <dst> to answer, printing how
# long it took; fails after <max-seconds>.
recovers() {
	i=0
	while [ $i -lt "$3" ]; do
		if nsx "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; then echo $i; return 0; fi
		i=$((i + 1))
	done
	return 1
}
nsx() { ns=$1; shift; ip netns exec "$ns" "$@"; }

apk add -q wireguard-tools-wg nftables iproute2 socat tcpdump iputils-ping coreutils >/dev/null

# --- topology ---
for ns in inet client client2 gw1 gw2 lan1 lan2; do
	ip netns add $ns
	nsx $ns ip link set lo up
done
veth() { # veth <ns-a> <if-a> <addr-a> <ns-b> <if-b> <addr-b>
	ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
	nsx "$1" ip addr add "$3" dev "$2"; nsx "$1" ip link set "$2" up
	nsx "$4" ip addr add "$6" dev "$5"; nsx "$4" ip link set "$5" up
}
# gw1: a management interface exists before WAN and LAN (worst case for
# kernel ICMP source selection); gw2: LAN first.
nsx gw1 ip link add mgmt0 type dummy
nsx gw1 ip addr add 192.168.99.1/24 dev mgmt0 && nsx gw1 ip link set mgmt0 up
veth inet g1 198.18.1.1/24 gw1 wan0 198.18.1.2/24
veth gw1 lan0 10.15.0.1/24 lan1 eth0 10.15.0.10/24
veth gw2 lan0 10.25.0.1/24 lan2 eth0 10.25.0.10/24
veth inet g2 198.18.2.1/24 gw2 wan0 198.18.2.2/24
veth inet c0 100.64.0.1/24 client eth0 100.64.0.2/24
veth inet c1 100.64.1.1/24 client2 eth0 100.64.1.2/24
nsx inet sysctl -qw net.ipv4.ip_forward=1
for ns in gw1 gw2; do
	nsx $ns sysctl -qw net.ipv4.ip_forward=1
	nsx $ns ip route add default via 198.18.${ns#gw}.1
done
nsx client ip route add default via 100.64.0.1
nsx client2 ip route add default via 100.64.1.1

# --- controller state and agents ---
cd "$WORK"
"$BIN/plaitctl" init-key psk.key 2>/dev/null
cat >plaitd.json <<EOF
{"database":"$WORK/plaitd.db","encryption_key_file":"$WORK/psk.key","client_pool":"10.0.0.0/24"}
EOF
export PLAIT_CONFIG=$WORK/plaitd.json

agent() { gw=$1; shift; nsx "$gw" "$BIN/plait-agent" "$@" -config "$WORK/$gw.json"; }
apply() { # apply <gw> <site>
	"$BIN/plaitctl" site snapshot "$2" 2>/dev/null >"$1.snap" &&
		nsx "$1" "$BIN/plait-agent" apply-file -config "$WORK/$1.json" "$1.snap" 2>>"$1.log"
}
for gw in gw1 gw2; do
	cat >$gw.json <<EOF
{"site_id":"probe","state_dir":"$WORK/$gw","nft_path":"$(command -v nft)"}
EOF
done
GW1_PUB=$(agent gw1 init 2>/dev/null)
GW2_PUB=$(agent gw2 init 2>/dev/null)
S1=$("$BIN/plaitctl" site add -name One -endpoint 198.18.1.2 -pubkey "$GW1_PUB" -egress lan0 -subnet 10.15.0.0/24)
S2=$("$BIN/plaitctl" site add -name Two -endpoint 198.18.2.2 -pubkey "$GW2_PUB" -egress lan0 -subnet 10.25.0.0/24)
sed -i "s/probe/$S1/" gw1.json
sed -i "s/probe/$S2/" gw2.json

enroll() { # enroll <name> <sites...>
	n=$1; shift
	wg genkey >"$n.key"
	"$BIN/plaitctl" device enroll "$n" -pubkey "$(wg pubkey <"$n.key")" >/dev/null
	for s in "$@"; do "$BIN/plaitctl" link add "$s" "$n" >/dev/null; done
}
enroll phone One Two
enroll laptop One

check "gw1 applies site One" apply gw1 One
check "gw2 applies site Two" apply gw2 Two

# client_up <ns> <device>: wg0 from a locally assembled profile, with a route
# per AllowedIPs entry (what wg-quick does).
client_up() {
	"$BIN/plaitctl" profile "$2" -private-key-file "$2.key" -minify 2>/dev/null >"$2.conf"
	addr=$(sed -n 's/^Address=//p' "$2.conf")
	grep -v -e '^Address=' -e '^DNS=' -e '^MTU=' "$2.conf" >"$2.wg"
	nsx "$1" ip link add wg0 type wireguard
	nsx "$1" wg setconf wg0 "$2.wg"
	nsx "$1" ip addr add "$addr" dev wg0
	nsx "$1" ip link set wg0 up mtu 1420
	for p in $(sed -n 's/^AllowedIPs=//p' "$2.conf" | tr ',' ' '); do nsx "$1" ip route add "$p" dev wg0; done
}
client_up client phone
client_up client2 laptop

# --- one /32 reaches both LANs concurrently ---
nsx client ping -c 20 -i 0.1 -W 1 10.15.0.10 >p1.log 2>&1 &
P1=$!
nsx client ping -c 20 -i 0.1 -W 1 10.25.0.10 >p2.log 2>&1 &
P2=$!
wait $P1 $P2 || true
check "one client /32 reaches LAN One while reaching LAN Two" grep -q " 0% packet loss" p1.log
check "one client /32 reaches LAN Two while reaching LAN One" grep -q " 0% packet loss" p2.log
PHONE=$(wg pubkey <phone.key)
psk() { nsx "$1" wg show plait0 preshared-keys | awk -v k="$PHONE" '$1 == k {print $2}'; }
check "each link has its own PSK" sh -c "[ -n '$(psk gw1)' ] && [ '$(psk gw1)' != '$(psk gw2)' ]"
check "the phone's profile carries one peer per site" sh -c "[ \$(grep -c '^\[Peer\]' phone.conf) = 2 ]"

# --- MSS clamping (plait0 MTU 1420: clamp 1380) ---
nsx lan1 socat TCP-LISTEN:7000,fork,reuseaddr SYSTEM:true 2>/dev/null &
# mss <ns> <filter>: the MSS option of the first matching segment seen on <ns>'s interface.
mss() {
	ns=$1 iface=$2 flags=$3; shift 3
	nsx "$ns" timeout 4 tcpdump -nvli "$iface" -c1 "tcp port 7000 and tcp[tcpflags] == $flags" 2>/dev/null >mss.cap &
	sleep 1
	nsx client socat -T 2 /dev/null TCP:10.15.0.10:7000,connect-timeout=2 2>/dev/null || true
	wait $! || true
	grep -o 'mss [0-9]*' mss.cap | head -1 | cut -d' ' -f2
}
nsx client ip link set wg0 mtu 1500 # a client-selected MTU larger than the site's
SYN=$(mss lan1 eth0 tcp-syn)
SYNACK=$(mss client wg0 '(tcp-syn|tcp-ack)')
note "client wg0 MTU 1500: SYN MSS at LAN $SYN, SYN-ACK MSS at client $SYNACK"
check "SYN MSS clamped to 1380 toward the LAN" [ "$SYN" = 1380 ]
check "SYN-ACK MSS clamped to 1380 toward the client" [ "$SYNACK" = 1380 ]
nsx client ip link set wg0 mtu 1420
nsx client ip route replace 10.15.0.0/24 dev wg0 advmss 1000
SYN=$(mss lan1 eth0 tcp-syn)
check "a smaller SYN MSS (1000) is preserved" [ "$SYN" = 1000 ]
nsx client ip route replace 10.15.0.0/24 dev wg0
nsx lan1 ip route replace 10.15.0.0/24 dev eth0 advmss 1100
SYNACK=$(mss client wg0 '(tcp-syn|tcp-ack)')
check "a smaller SYN-ACK MSS (1100) is preserved" [ "$SYNACK" = 1100 ]
nsx lan1 ip route replace 10.15.0.0/24 dev eth0

# --- gateway-generated ICMP errors (SPEC §2.3) ---
# icmp_reaches <gw-lan-addr> <lan-host> <ping args>: an error from the
# gateway's LAN address arrives on the client's wg0.
icmp_reaches() {
	src=$1 dst=$2; shift 2
	: >icmp.cap
	nsx client timeout 4 tcpdump -nli wg0 -c1 'icmp[0] == 3 or icmp[0] == 11' >icmp.cap 2>/dev/null &
	sleep 1
	nsx client ping -c 1 -W 1 "$@" "$dst" || true
	wait $! || true
	grep -q " IP $src > 10.0.0.2: ICMP" icmp.cap
}
for gw in gw1 gw2; do
	n=${gw#gw}; lan=10.$((n * 10 + 5)).0
	check "$gw: TTL exceeded reaches the client from $lan.1" icmp_reaches $lan.1 $lan.10 -t 1
	nsx $gw ip link set lan0 mtu 1280
	check "$gw: Fragmentation Needed reaches the client from $lan.1" icmp_reaches $lan.1 $lan.10 -M do -s 1300
	check "$gw: the client learned path MTU 1280 from it" sh -c "ip netns exec client ip route get $lan.10 | grep -q 'mtu 1280'"
	nsx $gw ip link set lan0 mtu 1500
done

# --- bulk TCP and UDP under a reduced underlay MTU ---
head -c 16777216 /dev/urandom >blob
SUM=$(sha256sum <blob | cut -d' ' -f1)
tcp_up() { # tcp_up <port>: client -> LAN One, verified by checksum
	rm -f up.out
	nsx lan1 timeout 60 socat -u TCP-LISTEN:$1,reuseaddr CREATE:up.out 2>/dev/null &
	sleep 0.5
	nsx client timeout 60 socat -u FILE:blob TCP:10.15.0.10:$1 && wait $! &&
		[ "$(sha256sum <up.out | cut -d' ' -f1)" = "$SUM" ]
}
tcp_down() { # tcp_down <port>: LAN One -> client
	rm -f down.out
	nsx lan1 timeout 60 socat -u FILE:blob TCP-LISTEN:$1,reuseaddr 2>/dev/null &
	sleep 0.5
	nsx client timeout 60 socat -u TCP:10.15.0.10:$1 CREATE:down.out && wait $! &&
		[ "$(sha256sum <down.out | cut -d' ' -f1)" = "$SUM" ]
}
# udp_up / udp_down: send the datagram in dgram to / from LAN One, up to two
# attempts; print the attempt that arrived intact. A DF datagram larger than
# the path loses its first copy while the sender learns the path MTU from an
# ICMP error, as for any UDP over a smaller-MTU hop.
udp_up() {
	for a in 1 2; do
		rm -f u.out
		nsx lan1 timeout 5 socat -u -T 2 UDP-RECV:7100 CREATE:u.out 2>/dev/null &
		sleep 0.5
		nsx client socat -u FILE:dgram UDP-SENDTO:10.15.0.10:7100
		wait $! || true
		if cmp -s dgram u.out; then echo $a; return 0; fi
	done
	return 1
}
udp_down() { # the LAN host can only answer the masquerade address: reply to a trigger
	for a in 1 2; do
		nsx lan1 timeout 5 socat UDP-RECVFROM:7102 SYSTEM:"cat $WORK/dgram" 2>/dev/null &
		sleep 0.5
		echo go | nsx client timeout 5 socat -t 2 - UDP:10.15.0.10:7102 >u.out 2>/dev/null || true
		wait $! || true
		if cmp -s dgram u.out; then echo $a; return 0; fi
	done
	return 1
}
udp_check() { # udp_check <label> <size>
	head -c "$2" /dev/urandom >dgram
	for dir in up down; do
		if a=$(udp_$dir); then
			pass "$1: UDP $2-byte datagram $dir"
			[ "$a" = 1 ] || note "$1: UDP $2-byte datagram $dir arrived on attempt $a (path MTU learned from the first)"
		else
			fail "$1: UDP $2-byte datagram $dir"
		fi
	done
}
# fragments: IP fragments created so far by the router, gw1, and the client.
fragments() {
	t=0
	for ns in inet gw1 client; do
		n=$(nsx $ns awk '/^Ip:/ { if (!c) { for (i = 1; i <= NF; i++) if ($i == "FragCreates") c = i } else print $c }' /proc/net/snmp)
		t=$((t + n))
	done
	echo $t
}
underlay() { nsx inet ip link set g1 mtu "$1"; nsx gw1 ip link set wan0 mtu "$1"; }

port=7200
F0=$(fragments)
for u in 1500 1380; do
	underlay $u
	for size in 1200 1400 4000; do udp_check "underlay $u" $size; done
	port=$((port + 2))
	check "underlay $u: 16 MiB TCP upload intact" tcp_up $port
	check "underlay $u: 16 MiB TCP download intact" tcp_down $((port + 1))
done
note "plait0 MTU 1420 over underlays 1500 and 1380: $(($(fragments) - F0)) IP fragments created; the clamp is plait0 MTU - 40, not route PMTU"

# A site MTU matching the underlay avoids outer fragmentation.
"$BIN/plaitctl" site update One -mtu 1320
check "gw1 applies site MTU 1320" apply gw1 One
check "plait0 MTU follows the site" sh -c "ip netns exec gw1 ip link show plait0 | grep -q 'mtu 1320'"
nsx client ip link set wg0 mtu 1320
F0=$(fragments)
check "site MTU 1320, underlay 1380: 16 MiB TCP upload intact" tcp_up 7300
check "site MTU 1320, underlay 1380: 16 MiB TCP download intact" tcp_down 7301
FRAGS=$(($(fragments) - F0))
note "site MTU 1320 over underlay 1380: $FRAGS IP fragments created during bulk TCP"
check "no fragmentation at site MTU 1320 over underlay 1380" [ "$FRAGS" = 0 ]
underlay 1500
nsx client ip link set wg0 mtu 1420
"$BIN/plaitctl" site update One -mtu 1420
apply gw1 One

# --- reverse-path filtering (the agent reports it; never changes it) ---
before=$(nsx gw1 sysctl -n net.ipv4.conf.wan0.rp_filter net.ipv4.conf.lan0.rp_filter | tr '\n' ' ')
for mode in "1 0" "1 2" "2 0"; do
	set -- $mode
	nsx gw1 sysctl -qw net.ipv4.conf.all.rp_filter=$1 net.ipv4.conf.plait0.rp_filter=$2
	check "rp_filter all=$1 plait0=$2: client reaches LAN One" nsx client ping -c 2 -W 2 10.15.0.10
done
nsx gw1 sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.plait0.rp_filter=0
check "strict rp_filter: apply verifies" apply gw1 One
after=$(nsx gw1 sysctl -n net.ipv4.conf.wan0.rp_filter net.ipv4.conf.lan0.rp_filter | tr '\n' ' ')
check "agent left other interfaces' rp_filter alone" [ "$before" = "$after" ]
nsx gw1 ip route del 10.0.0.2/32 dev plait0
check_not "strict rp_filter drops client traffic without the return route" nsx client ping -c 2 -W 1 10.15.0.10
check "apply restores the return route" apply gw1 One
check "traffic recovers under strict rp_filter" nsx client ping -c 2 -W 2 10.15.0.10

# --- an unrelated flow survives adding and revoking other peers ---
nsx lan1 timeout 30 socat -u TCP-LISTEN:7400,reuseaddr CREATE:flow.out 2>/dev/null &
LISTEN=$!
sleep 0.5
nsx client2 sh -c 'for i in $(seq 80); do echo $i; sleep 0.1; done' >flow.in
nsx client2 sh -c "for i in \$(seq 80); do echo \$i; sleep 0.1; done | socat -u - TCP:10.15.0.10:7400" &
FLOW=$!
sleep 1
enroll tablet One
check "apply adding a peer during the flow verifies" apply gw1 One
"$BIN/plaitctl" device disable phone
check "apply revoking a peer during the flow verifies" apply gw1 One
wait $FLOW $LISTEN || true
check "the laptop's TCP flow delivered every line across both changes" cmp -s flow.in flow.out
check_not "the revoked phone lost LAN One" nsx client ping -c 2 -W 1 10.15.0.10

# --- re-enabling a revoked device ---
# The gateway removed the phone's peer, so the client's session is stale; it
# re-handshakes only after hearing nothing back for keepalive + rekey timeout
# (about 15 s). This is WireGuard behavior, recorded rather than hidden.
"$BIN/plaitctl" device enable phone
apply gw1 One
if T=$(recovers client 10.15.0.10 40); then
	pass "phone reaches LAN One again after re-enable"
	note "re-enabled phone recovered LAN One after ${T}s (stale client session)"
else
	fail "phone reaches LAN One again after re-enable"
fi

# --- one site's failure does not affect another ---
check "phone reaches LAN Two before the failure" nsx client ping -c 2 -W 2 10.25.0.10
nsx client ping -c 40 -i 0.25 -W 1 10.15.0.10 >site1.log 2>&1 &
PING=$!
agent gw2 uninstall 2>/dev/null
check_not "site Two down" nsx client ping -c 2 -W 1 10.25.0.10
wait $PING || true
check "LAN One saw no loss while site Two failed" grep -q " 0% packet loss" site1.log
check "site Two recovers" apply gw2 Two
if T=$(recovers client 10.25.0.10 40); then
	pass "phone reaches LAN Two again"
	note "phone recovered LAN Two ${T}s after plait0 was recreated (stale client session)"
else
	fail "phone reaches LAN Two again"
fi

DONE=1
echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
	for gw in gw1 gw2; do echo "--- $gw log ---"; cat "$gw.log"; done
	exit 1
fi
