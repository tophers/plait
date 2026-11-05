# Shared setup for the Linux integration harnesses: helpers and the test
# topology. Sourced by agent-integration.sh and controller-integration.sh.
#
#   client ns (10.0.0.x/32 on wg0) --wan-- gateway (plait0, wan0, lan0) --lan-- lan ns
#      192.0.2.2                           192.0.2.1   10.15.0.1          10.15.0.10
#   client2 ns                   --wan2--  192.0.3.1                      10.16.0.10 (unadvertised)
#      192.0.3.2
#
# The LAN host has no route to the client pool, so replies only work through
# the gateway's masquerade.

BIN=${BIN:-/plait/bin}
WORK=$(mktemp -d)
PASS=0
FAIL=0
# set -e aborts silently; make an early exit a visible failure.
trap '[ "${DONE:-}" = 1 ] || { echo "HARNESS ABORTED (passed: $PASS failed: $FAIL)"; exit 1; }' EXIT

pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
check() { desc=$1; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
check_not() { desc=$1; shift; if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi; }
in_client() { ip netns exec client "$@"; }
in_client2() { ip netns exec client2 "$@"; }

apk add -q wireguard-tools-wg nftables iproute2 curl jq >/dev/null

# --- topology ---
sysctl -qw net.ipv4.ip_forward=1
ip netns add client
ip netns add client2
ip netns add lan

ip link add wan0 type veth peer name eth0 netns client
ip addr add 192.0.2.1/24 dev wan0 && ip link set wan0 up
in_client ip addr add 192.0.2.2/24 dev eth0
in_client ip link set eth0 up && in_client ip link set lo up

ip link add wan2 type veth peer name eth0 netns client2
ip addr add 192.0.3.1/24 dev wan2 && ip link set wan2 up
ip netns exec client2 ip addr add 192.0.3.2/24 dev eth0
ip netns exec client2 ip link set eth0 up

ip link add lan0 type veth peer name eth0 netns lan
ip addr add 10.15.0.1/24 dev lan0 && ip addr add 10.16.0.1/24 dev lan0 && ip link set lan0 up
ip netns exec lan ip addr add 10.15.0.10/24 dev eth0
ip netns exec lan ip addr add 10.16.0.10/24 dev eth0
ip netns exec lan ip link set eth0 up

# client_up brings up wg0 in a namespace from a locally assembled profile.
# Args: namespace, private key file, device name, [endpoint override].
client_up() {
  "$BIN/plaitctl" profile "$3" -private-key-file "$2" -minify 2>/dev/null >"$3.conf"
  addr=$(sed -n 's/^Address=//p' "$3.conf")
  grep -v -e '^Address=' -e '^DNS=' -e '^MTU=' "$3.conf" >"$3.wg"
  if [ -n "${4:-}" ]; then sed -i "s/^Endpoint=.*/Endpoint=$4/" "$3.wg"; fi
  ip netns exec "$1" ip link add wg0 type wireguard
  ip netns exec "$1" wg setconf wg0 "$3.wg"
  ip netns exec "$1" ip addr add "$addr" dev wg0
  ip netns exec "$1" ip link set wg0 up
  for p in $(sed -n 's/^AllowedIPs=//p' "$3.conf" | tr ',' ' '); do
    ip netns exec "$1" ip route add "$p" dev wg0
  done
}
