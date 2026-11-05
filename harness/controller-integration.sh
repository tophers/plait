#!/bin/sh
# Phase 3 end-to-end test: plaitd serving the REST API, an agent enrolled by
# token running its polling loop, and a real WireGuard client. Runs inside a
# privileged Linux container (see run-in-docker.sh); lib.sh describes the
# topology.
set -eu
umask 077

. "$(dirname "$0")/lib.sh"

API=http://127.0.0.1:8080
cd "$WORK"

# --- controller ---
"$BIN/plaitctl" init-key psk.key 2>/dev/null
printf '{"database":"%s/plaitd.db","encryption_key_file":"%s/psk.key","client_pool":"10.0.0.0/24","listen":"127.0.0.1:8080"}\n' \
  "$WORK" "$WORK" >plaitd.json
export PLAIT_CONFIG=$WORK/plaitd.json
ADMIN_PW="harness admin password"
echo "$ADMIN_PW" | "$BIN/plaitctl" admin create admin

start_plaitd() {
  "$BIN/plaitd" -config plaitd.json >>plaitd.log 2>&1 &
  PLAITD=$!
  for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && return 0; sleep 0.1; done
  echo "plaitd did not start"; cat plaitd.log; return 1
}
start_plaitd

# Admin API helpers: cookie jar plus CSRF header. curl will not send a Secure
# cookie over plain HTTP, so clear the secure flag in the jar (loopback only).
login() {
  CSRF=$(curl -sf -c jar -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" "$API/api/v1/admin/login" | jq -r .csrf_token)
  awk 'BEGIN{FS=OFS="\t"} NF==7 {$4="FALSE"} {print}' jar >jar.tmp && mv jar.tmp jar
}
api() { # method path [json]
  if [ $# -ge 3 ]; then
    curl -sf -b jar -X "$1" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "$3" "$API$2"
  else
    curl -sf -b jar -X "$1" -H "X-CSRF-Token: $CSRF" "$API$2"
  fi
}
login
check "admin session established" api GET /api/v1/admin/session
check_not "admin API rejects requests without a session" curl -sf "$API/api/v1/admin/sites"

# Wait up to $1 seconds for a command to succeed (the agent polls every ~15s).
wait_for() { secs=$1; shift; for _ in $(seq "$secs"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
jqsite() { api GET "/api/v1/admin/sites/$SITE_ID$1" | jq -e "$2"; }
jqdev() { api GET "/api/v1/admin/devices/$DEV_ID" | jq -e "$1"; }

# --- site enrollment by token ---
SITE_ID=$(api POST /api/v1/admin/sites '{"name":"Lab","endpoint_host":"192.0.2.1","egress_interface":"lan0","subnets":["10.15.0.0/24"]}' | jq -r .id)
check "new site is pending enrollment" jqsite "" .pending_enrollment
TOKEN=$(api POST "/api/v1/admin/sites/$SITE_ID/enrollment-token" | jq -r .token)

mkdir -p /etc/plait
printf '{"state_dir":"%s/agent","nft_path":"%s","credential_file":"%s/agent/credential"}\n' \
  "$WORK" "$(command -v nft)" "$WORK" >/etc/plait/agent.json
check "agent enrolls with the token" "$BIN/plait-agent" enroll -controller "$API" -token "$TOKEN"
check_not "enrollment token is single use" "$BIN/plait-agent" enroll -controller "$API" -token "$TOKEN"
check "agent config records the site" jq -e ".site_id == \"$SITE_ID\"" /etc/plait/agent.json
check "site no longer pending" jqsite "" '.pending_enrollment == false'

# --- device and link via the admin API ---
wg genkey >client.key
DEV_ID=$(api POST /api/v1/admin/devices "{\"name\":\"phone\",\"public_key\":\"$(wg pubkey <client.key)\"}" | jq -r .id)
api POST /api/v1/admin/links "{\"site_id\":\"$SITE_ID\",\"device_id\":\"$DEV_ID\"}" >/dev/null

"$BIN/plait-agent" run >>agent.log 2>&1 &
AGENT=$!

applied() { jqsite /status '.applied_revision == .desired_revision and .reachability == "reachable" and .health == "healthy"'; }
check "agent applies desired state and reports healthy" wait_for 30 applied

client_up client client.key phone
check "client reaches LAN through the controller-provisioned gateway" in_client ping -c 2 -W 2 10.15.0.10

# --- revocation through the API propagates observably ---
api POST "/api/v1/admin/devices/$DEV_ID/disable" >/dev/null
check "revocation shown pending before acknowledgment" jqdev .revocation_pending
check "agent acknowledges the revocation" wait_for 30 applied
check "revocation no longer pending" jqdev '.revocation_pending == false'
check_not "revoked client cannot reach LAN" in_client ping -c 2 -W 1 10.15.0.10

api POST "/api/v1/admin/devices/$DEV_ID/enable" >/dev/null
check "re-enabled device applied" wait_for 30 applied
# The client's handshake attempts went unanswered while revoked; WireGuard
# retries on its own ~5s schedule, so allow a few retry intervals.
check "client reaches LAN again" wait_for 15 in_client ping -c 1 -W 1 10.15.0.10

# --- controller outage: the agent continues from cache and repairs drift ---
kill "$PLAITD"; wait "$PLAITD" 2>/dev/null || true
ip route del 10.0.0.2/32 dev plait0
check "agent repairs drift while the controller is down" wait_for 30 sh -c 'ip route show dev plait0 | grep -q "^10.0.0.2 "'
check "client keeps working during the outage" in_client ping -c 2 -W 2 10.15.0.10
check "agent logged the outage" grep -q "controller unavailable" agent.log

start_plaitd
login
check "after controller restart, live status is unknown" jqsite /status '.reachability == "unknown" and .health == "unknown"'
check "acknowledged revision survived the restart" jqsite /status '.applied_revision == .desired_revision'
# The agent backs off after failures (up to 5 minutes), so allow for that.
check "agent becomes reachable again after reporting" wait_for 330 applied

# --- backup, restore, and recovery ---
"$BIN/plaitctl" backup "$WORK/backup.db" 2>/dev/null
api POST "/api/v1/admin/devices/$DEV_ID/disable" >/dev/null   # revoked after the backup
check "post-backup revocation applied" wait_for 30 applied
check_not "post-backup revocation blocks the client" in_client ping -c 2 -W 1 10.15.0.10
kill "$PLAITD"; wait "$PLAITD" 2>/dev/null || true
check "restore enters recovery" sh -c "'$BIN/plaitctl' restore '$WORK/backup.db' 2>/dev/null"
start_plaitd
login
check "restored database predates the revocation" jqdev '.enabled'
check_not "desired state withheld during recovery" \
  curl -sf -H "Authorization: Bearer $(cat "$WORK/agent/credential")" "$API/api/v1/agent/sync"
check "agent keeps reporting during recovery and is shown ahead" \
  wait_for 40 jqsite /status '.agent_ahead_of_controller and .reachability == "reachable"'
check "recover status flags the site" sh -c "'$BIN/plaitctl' recover status | grep -q 'agent is ahead'"
check_not "revocation still enforced at the gateway during recovery" in_client ping -c 2 -W 1 10.15.0.10
api POST "/api/v1/admin/devices/$DEV_ID/disable" >/dev/null   # administrator re-applies it
check "recovery completes" sh -c "'$BIN/plaitctl' recover complete 2>/dev/null"
check "agent applies the advanced revision" wait_for 40 applied
check "agent no longer ahead" jqsite /status '.agent_ahead_of_controller == false'
check_not "revoked device stays revoked after recovery" in_client ping -c 2 -W 1 10.15.0.10
api POST "/api/v1/admin/devices/$DEV_ID/enable" >/dev/null
check "access restored after recovery" wait_for 30 applied
check "client reaches LAN after recovery" wait_for 15 in_client ping -c 1 -W 1 10.15.0.10

# --- credential rotation and revocation ---
OLD_CRED=$(cat "$WORK/agent/credential")
check "agent rotates its credential" "$BIN/plait-agent" rotate-credential
check "credential file replaced" sh -c "[ \"\$(cat '$WORK/agent/credential')\" != '$OLD_CRED' ]"
api POST "/api/v1/admin/sites/$SITE_ID/credentials/revoke" >/dev/null
check "agent reports its credential was rejected" wait_for 30 grep -q "credential rejected" agent.log
check "gateway keeps serving cached peers after credential revocation" in_client ping -c 2 -W 2 10.15.0.10

# --- secrets never reach logs, status, or audit ---
PSK=$(api GET "/api/v1/admin/devices/$DEV_ID/profile-material" | jq -r '.peers[0].preshared_key')
api GET "/api/v1/admin/sites/$SITE_ID/status" >status.json
api GET '/api/v1/admin/audit?limit=500' >audit.json
for f in plaitd.log agent.log status.json audit.json; do
  check_not "$f has no PSK" grep -qF "$PSK" "$f"
  check_not "$f has no enrollment token" grep -qF "$TOKEN" "$f"
  check_not "$f has no agent credential" grep -qF "$OLD_CRED" "$f"
  check_not "$f has no client private key" grep -qF "$(cat client.key)" "$f"
  check_not "$f has no gateway private key" grep -qF "$(cat "$WORK/agent/gateway.key")" "$f"
  check_not "$f has no admin password" grep -qF "$ADMIN_PW" "$f"
done
check "audit records enrollment, revocation, and acknowledgments" \
  jq -e '[.[].action] | (index("site.enroll") and index("device.disable") and index("site.applied") and index("site.credentials_revoke"))' audit.json

kill "$AGENT" "$PLAITD" 2>/dev/null || true
"$BIN/plait-agent" uninstall 2>/dev/null || true

DONE=1
echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "--- plaitd log (tail) ---"; tail -30 plaitd.log
  echo "--- agent log (tail) ---"; tail -30 agent.log
  exit 1
fi
