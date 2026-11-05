#!/bin/sh
# Phase 4 check: a profile assembled by plaitd's browser code (run under
# Node from internal/ui/static) is imported into a real WireGuard client and
# carries traffic through an agent-managed gateway. Runs inside a privileged
# Linux container (see run-in-docker.sh); lib.sh describes the topology.
set -eu
umask 077

. "$(dirname "$0")/lib.sh"
apk add -q nodejs >/dev/null

API=http://127.0.0.1:8080
STATIC=/plait/static
cd "$WORK"

"$BIN/plaitctl" init-key psk.key 2>/dev/null
printf '{"database":"%s/plaitd.db","encryption_key_file":"%s/psk.key","client_pool":"10.0.0.0/24","listen":"127.0.0.1:8080"}\n' \
  "$WORK" "$WORK" >plaitd.json
export PLAIT_CONFIG=$WORK/plaitd.json
ADMIN_PW="harness admin password"
echo "$ADMIN_PW" | "$BIN/plaitctl" admin create admin
"$BIN/plaitd" -config plaitd.json >>plaitd.log 2>&1 &
PLAITD=$!
for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.1; done

LOGIN=$(curl -sf -c jar -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" "$API/api/v1/admin/login")
CSRF=$(echo "$LOGIN" | jq -r .csrf_token)
COOKIE="plait_session=$(awk '$6 == "plait_session" {print $7}' jar)"
api() { curl -sf -X "$1" -H "X-CSRF-Token: $CSRF" -H "Cookie: $COOKIE" -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2"; }

check "UI login page served with CSP" sh -c "curl -sfI $API/login | grep -qi \"content-security-policy: default-src 'none'; script-src 'self'\""
check "UI serves the vendored X25519 bundle it was built with" sh -c "curl -sf $API/static/vendor/x25519.js | cmp -s - $STATIC/vendor/x25519.js"

SITE_ID=$(api POST /api/v1/admin/sites '{"name":"Lab","endpoint_host":"192.0.2.1","egress_interface":"lan0","subnets":["10.15.0.0/24"]}' | jq -r .id)
TOKEN=$(api POST "/api/v1/admin/sites/$SITE_ID/enrollment-token" | jq -r .token)
mkdir -p /etc/plait
printf '{"state_dir":"%s/agent","nft_path":"%s","credential_file":"%s/agent/credential"}\n' "$WORK" "$(command -v nft)" "$WORK" >/etc/plait/agent.json
"$BIN/plait-agent" enroll -controller "$API" -token "$TOKEN" 2>/dev/null

# Enroll a device exactly as the browser does.
JS_PUB=$(node /plait/harness/browser-assemble.mjs "$STATIC" "$API" "$CSRF" "$COOKIE" "$SITE_ID" browser-phone browser.conf browser.key)
check "browser-generated key derives the same public key as wg pubkey" sh -c "[ \"\$(wg pubkey <browser.key)\" = '$JS_PUB' ]"

"$BIN/plait-agent" run >>agent.log 2>&1 &
AGENT=$!
applied() { api GET "/api/v1/admin/sites/$SITE_ID/status" | jq -e '.applied_revision == .desired_revision and .health == "healthy"'; }
wait_for() { secs=$1; shift; for _ in $(seq "$secs"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
check "agent applies the browser-enrolled device" wait_for 30 applied

# Import the browser-assembled profile into a real client.
addr=$(sed -n 's/^Address=//p' browser.conf)
grep -v -e '^Address=' -e '^DNS=' -e '^MTU=' browser.conf >browser.wg
in_client ip link add wg0 type wireguard
check "WireGuard accepts the browser-assembled profile" in_client wg setconf wg0 browser.wg
in_client ip addr add "$addr" dev wg0
in_client ip link set wg0 up
for p in $(sed -n 's/^AllowedIPs=//p' browser.conf | tr ',' ' '); do in_client ip route add "$p" dev wg0; done
check "browser-assembled profile reaches the site LAN" wait_for 10 in_client ping -c 1 -W 1 10.15.0.10
check "gateway peer is the browser-generated key" sh -c "wg show plait0 peers | grep -qF '$JS_PUB'"

kill "$AGENT" "$PLAITD" 2>/dev/null || true
"$BIN/plait-agent" uninstall 2>/dev/null || true

DONE=1
echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  tail -20 plaitd.log; tail -20 agent.log
  exit 1
fi
