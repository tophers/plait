#!/bin/sh
# Exercises packaging/install.sh on Debian trixie booted with systemd as
# PID 1: fresh controller and agent installs, an idempotent re-run,
# enrollment, an upgrade, permission repair, uninstall, and purge. Run from the host; needs
# Docker with WireGuard and nftables support in its kernel.
set -eu
cd "$(dirname "$0")/.."
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -o "bin/linux-$ARCH/" ./cmd/...

docker build -q -t plait-trixie-systemd - >/dev/null <<'EOF'
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus openssl curl && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

boot() {
	docker run -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
		--tmpfs /run --tmpfs /run/lock -v "$PWD:/src:ro" plait-trixie-systemd
}
C=$(boot)
CONTAINERS=$C
# KEEP=1 leaves the containers running for inspection.
[ "${KEEP:-}" = 1 ] || trap 'docker rm -f $CONTAINERS >/dev/null' EXIT
x() { docker exec "$C" sh -c "$*"; }

PASS=0 FAIL=0
check() {
	name=$1; shift
	if "$@" >/tmp/plait-install-check.log 2>&1; then
		PASS=$((PASS + 1)); echo "ok   $name"
	else
		FAIL=$((FAIL + 1)); echo "FAIL $name"; sed 's/^/     /' /tmp/plait-install-check.log
	fi
}

x 'systemctl is-system-running --wait >/dev/null 2>&1 || true'
INSTALL=/src/packaging/install.sh

echo "--- fresh controller install"
check "install controller (no TLS options)" x "$INSTALL controller --client-pool 10.99.0.0/24"
check "plaitd system user" x 'getent passwd plaitd | grep -q nologin'
check "plaitd active" x 'systemctl is-active -q plaitd'
check "psk.key plaitd 0600" x '[ "$(stat -c %U:%a /etc/plait/psk.key)" = plaitd:600 ]'
check "config uses generated TLS" x '! grep -q tls_cert_file /etc/plait/plaitd.json'
check "generated CA key plaitd 0600" x '[ "$(stat -c %U:%a /var/lib/plaitd/tls/ca.key)" = plaitd:600 ]'
check "server key plaitd 0600" x '[ "$(stat -c %U:%a /var/lib/plaitd/tls/server.key)" = plaitd:600 ]'
FP=$(x 'runuser -u plaitd -- plaitctl tls status' | sed -n 's/^ca_fingerprint: //p')
check "tls status shows CA fingerprint" test -n "$FP"
check "CA published at /ca.pem" x 'curl -sf --cacert /var/lib/plaitd/tls/ca.pem https://localhost:8443/ca.pem | cmp -s - /var/lib/plaitd/tls/ca.pem'
check "state dir plaitd 0700" x '[ "$(stat -c %U:%a /var/lib/plaitd)" = plaitd:700 ]'
check "admin create as plaitd" x 'printf "correct-horse-battery\n" | runuser -u plaitd -- plaitctl admin create admin'
LOGIN="curl -sf --cacert /var/lib/plaitd/tls/ca.pem -o /dev/null -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"correct-horse-battery\"}' https://localhost:8443/api/v1/admin/login"
check "admin login over TLS" x "$LOGIN"
PID1=$(x 'systemctl show -p MainPID --value plaitd')

echo "--- idempotent re-run"
check "re-run controller" x "$INSTALL controller | grep -q 'plaitd unchanged and running'"
check "plaitd not restarted" x "[ \"\$(systemctl show -p MainPID --value plaitd)\" = $PID1 ]"
check "no backup without upgrade" x '[ -z "$(ls /var/backups/plaitd)" ]'

echo "--- agent install and enrollment"
check "install agent (unenrolled)" x "$INSTALL agent | grep -q 'enroll this gateway'"
check "nftables installed" x 'command -v nft'
check "ip_forward enabled" x '[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ]'
check "agent not started before enrollment" x '! systemctl is-active -q plait-agent'
x 'runuser -u plaitd -- plaitctl site add -name Lab -endpoint 192.0.2.1 -egress eth0 -subnet 192.168.77.0/24 >/dev/null'
TOKEN=$(x 'runuser -u plaitd -- plaitctl site enroll-token Lab 2>/dev/null' | grep -o 'plaite_[A-Za-z0-9_-]*' | head -n1)
BADFP=sha256:$(printf '%064d' 0)
check "wrong CA fingerprint refused" x "! plait-agent enroll -controller https://localhost:8443 -token $TOKEN -ca-fingerprint $BADFP"
check "enroll with CA fingerprint" x "plait-agent enroll -controller https://localhost:8443 -token $TOKEN -ca-fingerprint $FP"
check "agent saved the pinned CA" x 'cmp -s /etc/plait/controller-ca.pem /var/lib/plaitd/tls/ca.pem'
check "re-run agent starts service" x "$INSTALL agent"
check "plait-agent active" x 'systemctl is-active -q plait-agent'
check "agent applies config" x 'for i in $(seq 30); do [ -d /sys/class/net/plait0 ] && \
	runuser -u plaitd -- plaitctl site status Lab 2>/dev/null | grep -q "\"applied_revision\": [1-9]" && exit 0; sleep 1; done; exit 1'
check "nft table present" x 'nft list table inet plait >/dev/null'

echo "--- gateway with a host-managed, flushing nftables config"
# Shaped like a GitOps-managed host firewall: flush, drop policies, plait*
# forwarding, the site's UDP port, and a glob include of conf.d.
x 'mkdir -p /etc/nftables/conf.d && cat >/etc/nftables.conf <<EOF
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
		udp dport { 51111 } accept
		tcp dport { 22, 8443 } accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		iifname "plait*" accept
		oifname "plait*" accept
	}
}
include "/etc/nftables/conf.d/*.nft"
EOF'
check "warns about flush ruleset without --nft-include" x "$INSTALL agent 2>&1 | grep -q 'runs .flush ruleset.'"
check "--nft-include configures the agent" x "$INSTALL agent --nft-include && grep -q '\"nft_include_file\": \"/etc/nftables/conf.d/plait.nft\"' /etc/plait/agent.json"
check "drop-in lets the sandboxed agent write there" x 'grep -qx "ReadWritePaths=-/etc/nftables/conf.d" /etc/systemd/system/plait-agent.service.d/nft-include.conf'
check "agent writes the include file" x 'for i in $(seq 30); do grep -q "^table inet plait {" /etc/nftables/conf.d/plait.nft 2>/dev/null && exit 0; sleep 1; done; exit 1'
check "host reload keeps Plait's table" x 'nft -f /etc/nftables.conf && nft list table inet plait >/dev/null && plait-agent status | grep -q "\"drift\": \[\]"'
IPID=$(x 'systemctl show -p MainPID --value plait-agent')
check "re-run keeps the include and does not restart" x "$INSTALL agent >/dev/null && [ \"\$(systemctl show -p MainPID --value plait-agent)\" = $IPID ]"
check "--no-nft-include removes file and drop-in" x "$INSTALL agent --no-nft-include >/dev/null && [ ! -e /etc/nftables/conf.d/plait.nft ] && \
	[ ! -e /etc/systemd/system/plait-agent.service.d/nft-include.conf ] && ! grep -q nft_include_file /etc/plait/agent.json"
x 'nft flush ruleset && rm /etc/nftables.conf && systemctl restart plait-agent'
check "agent restores its table after the host config is gone" x 'for i in $(seq 30); do nft list table inet plait >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
APID=$(x 'systemctl show -p MainPID --value plait-agent')
PID1=$(x 'systemctl show -p MainPID --value plaitd')

echo "--- upgrade"
x "rm -rf /tmp/up && cp -r /src/bin/linux-$ARCH /tmp/up && for f in /tmp/up/*; do printf upgrade >>\$f; done"
check "upgrade both roles" x "$INSTALL --bin-dir /tmp/up controller agent"
check "pre-upgrade backup taken" x 'ls /var/backups/plaitd/pre-upgrade-*.db'
check "previous binary kept" x 'cmp -s /usr/local/bin/plaitd.prev /src/bin/linux-'"$ARCH"'/plaitd'
check "plaitd restarted" x "[ \"\$(systemctl show -p MainPID --value plaitd)\" != $PID1 ] && systemctl is-active -q plaitd"
check "agent restarted" x "[ \"\$(systemctl show -p MainPID --value plait-agent)\" != $APID ] && systemctl is-active -q plait-agent"
check "admin login after upgrade" x "for i in \$(seq 10); do $LOGIN && exit 0; sleep 1; done; exit 1"

echo "--- permission repair"
x 'touch /var/lib/plaitd/stray && chmod 0644 /etc/plait/psk.key'
check "re-run repairs ownership" x "$INSTALL --bin-dir /tmp/up controller >/dev/null"
check "stray root file chowned" x '[ "$(stat -c %U /var/lib/plaitd/stray)" = plaitd ]'
check "psk.key mode restored" x '[ "$(stat -c %a /etc/plait/psk.key)" = 600 ]'

echo "--- Let's Encrypt"
x 'for n in a.example b.example; do d=/etc/letsencrypt/live/$n; mkdir -p $d && openssl req -x509 -newkey ec \
	-pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=$n -addext subjectAltName=DNS:localhost \
	-keyout $d/privkey.pem -out $d/fullchain.pem 2>/dev/null; done'
SERVED='echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null | openssl x509 -noout -subject -issuer'
check "several certificates need a choice" x "$INSTALL --bin-dir /tmp/up controller --letsencrypt 2>&1 | grep -q 'a.example b.example'"
check "choose one from the menu" x "printf '2\\n' | script -qec '$INSTALL --bin-dir /tmp/up controller --letsencrypt' /dev/null"
check "config points at the copied certificate" x 'grep -q "\"tls_cert_file\": \"/etc/plait/tls/cert.pem\"" /etc/plait/plaitd.json'
check "serves the chosen certificate" x "$SERVED | grep -q 'subject=CN=b.example'"
check "renewal hook installed" x '[ -x /etc/letsencrypt/renewal-hooks/deploy/plait ] && grep -qx b.example /etc/plait/tls/letsencrypt-lineage'
PID1=$(x 'systemctl show -p MainPID --value plaitd')
x 'd=/etc/letsencrypt/live/b.example; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
	-subj /CN=b-renewed -addext subjectAltName=DNS:localhost -keyout $d/privkey.pem -out $d/fullchain.pem 2>/dev/null'
check "renewal hook ignores other lineages" x 'cp /etc/plait/tls/cert.pem /tmp/before && \
	RENEWED_LINEAGE=/etc/letsencrypt/live/a.example /etc/letsencrypt/renewal-hooks/deploy/plait && cmp -s /tmp/before /etc/plait/tls/cert.pem'
check "renewal picked up without restart" x "RENEWED_LINEAGE=/etc/letsencrypt/live/b.example /etc/letsencrypt/renewal-hooks/deploy/plait && \
	for i in \$(seq 45); do $SERVED | grep -q 'CN=b-renewed' && exit 0; sleep 1; done; exit 1"
check "plaitd kept running" x "[ \"\$(systemctl show -p MainPID --value plaitd)\" = $PID1 ]"
check "re-run keeps Let's Encrypt" x "$INSTALL --bin-dir /tmp/up controller | grep -q 'plaitd unchanged and running'"
# A wildcard certificate's lineage name is not the controller's name.
check "a name the certificate does not cover is flagged" x "$INSTALL --bin-dir /tmp/up controller --controller-name wg.b.example >/tmp/name1.log 2>&1; \
	grep -q 'does not cover wg.b.example' /tmp/name1.log"
check "controller name recorded" x 'grep -qx wg.b.example /etc/plait/controller-name'
check "web UI hint uses the controller name" x 'grep -q "web UI: https://wg.b.example:8443/" /tmp/name1.log'
check "a covered name passes" x "$INSTALL --bin-dir /tmp/up controller --controller-name localhost >/tmp/name2.log 2>&1; \
	! grep -q 'does not cover' /tmp/name2.log && grep -q 'web UI: https://localhost:8443/' /tmp/name2.log"
check "Let's Encrypt kept throughout" x 'grep -q tls_cert_file /etc/plait/plaitd.json && grep -qx b.example /etc/plait/tls/letsencrypt-lineage'

echo "--- back to a generated certificate"
check "switch with --tls-auto" x "$INSTALL --bin-dir /tmp/up controller --tls-auto"
check "renewal hook removed" x '[ ! -e /etc/letsencrypt/renewal-hooks/deploy/plait ] && [ ! -e /etc/plait/tls/letsencrypt-lineage ]'
check "serves the generated certificate" x "$SERVED | grep -q 'issuer=CN=Plait controller CA'"
check "CA fingerprint unchanged" x "runuser -u plaitd -- plaitctl tls status | grep -qx 'ca_fingerprint: $FP'"
check "enrolled agent still trusts the controller" x 'plait-agent rotate-credential'

echo "--- interactive first install"
x 'mv /etc/plait/plaitd.json /root/plaitd.json.saved'
check "prompts for pool and TLS choice" x "printf '\\n3\\n' | script -qec '$INSTALL --bin-dir /tmp/up controller' /dev/null >/tmp/interactive.log; \
	grep -q 'Client address pool \\[10.99.0.0/24\\]' /tmp/interactive.log && grep -q '1) generate and renew one automatically' /tmp/interactive.log"
check "default pool and chosen certificate written" x 'grep -q "\"client_pool\": \"10.99.0.0/24\"" /etc/plait/plaitd.json && grep -q tls_cert_file /etc/plait/plaitd.json'
check "serves the certificate chosen interactively" x "$SERVED | grep -q 'subject=CN=b-renewed' && systemctl is-active -q plaitd"

echo "--- uninstall keeps the Let's Encrypt choice"
check "renewal hook present before uninstall" x '[ -x /etc/letsencrypt/renewal-hooks/deploy/plait ]'
check "--uninstall controller" x "$INSTALL --uninstall controller >/tmp/un1.log && ! systemctl is-active -q plaitd && [ ! -e /usr/local/bin/plaitd ]"
check "hook removed, lineage marker kept" x '[ ! -e /etc/letsencrypt/renewal-hooks/deploy/plait ] && [ -f /etc/plait/tls/letsencrypt-lineage ]'
check "agent left alone" x 'systemctl is-active -q plait-agent'
check "reinstall restores the hook" x "$INSTALL --bin-dir /tmp/up controller >/dev/null && [ -x /etc/letsencrypt/renewal-hooks/deploy/plait ] && systemctl is-active -q plaitd"

echo "--- prebuilt dist/ checksums"
if [ -f dist/SHA256SUMS ]; then
	x "rm -rf /tmp/good /tmp/bad && cp -r /src/dist /tmp/good && cp -r /src/dist /tmp/bad && printf x >>/tmp/bad/linux-$ARCH/plait-agent"
	check "verified dist binaries install" x "$INSTALL --no-deps --no-start --bin-dir /tmp/good/linux-$ARCH agent"
	check "tampered binary rejected" x "$INSTALL --no-deps --no-start --bin-dir /tmp/bad/linux-$ARCH agent 2>&1 | grep -q 'does not match'"
else
	echo "skip (no dist/; run make dist)"
fi

echo "--- guided setup (fresh host)"
C=$(boot)
CONTAINERS="$CONTAINERS $C"
[ "${KEEP:-}" = 1 ] && echo "containers: $CONTAINERS"
x 'systemctl is-system-running --wait >/dev/null 2>&1 || true'
# Answers: both roles, default pool and port, generated TLS with an extra
# name, proceed, create admin "admin" (password twice), skip enrollment.
x "printf '3\\n\\n\\n1\\nplait.test\\n\\n\\n\\ncorrect-horse-battery\\ncorrect-horse-battery\\n\\n' | \
	timeout 300 script -qec $INSTALL /dev/null >/tmp/wizard1.log 2>&1 || true"
check "wizard asks the questions" x 'grep -q "What should this host run?" /tmp/wizard1.log && grep -q "How should the controller handle TLS?" /tmp/wizard1.log && grep -q "This will install:" /tmp/wizard1.log'
check "wizard: plaitd running" x 'systemctl is-active -q plaitd'
check "wizard: extra TLS name recorded" x 'grep -q "\"tls_names\": \[\"plait.test\"\]" /etc/plait/plaitd.json'
check "wizard: certificate covers it and the host" x "echo | openssl s_client -connect localhost:8443 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -q 'DNS:plait.test' && \
	echo | openssl s_client -connect localhost:8443 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -q 'DNS:localhost'"
check "wizard: administrator created" x '[ "$(runuser -u plaitd -- plaitctl admin count)" = 1 ]'
check "wizard: prints the web UI address" x 'grep -q "web UI: https://plait.test:8443/" /tmp/wizard1.log'
check "wizard: gateway installed, waiting for enrollment" x 'command -v nft >/dev/null && ! systemctl is-active -q plait-agent && grep -q "Enrollment command" /tmp/wizard1.log'

echo "--- guided setup (re-run enrolls the gateway)"
x 'runuser -u plaitd -- plaitctl site add -name Lab -endpoint 192.0.2.1 -egress eth0 -subnet 192.168.77.0/24 >/dev/null'
TOKEN=$(x 'runuser -u plaitd -- plaitctl site enroll-token Lab 2>/dev/null' | grep -o 'plaite_[A-Za-z0-9_-]*' | head -n1)
FP=$(x 'runuser -u plaitd -- plaitctl tls status' | sed -n 's/^ca_fingerprint: //p')
# The host's nftables config flushes on reload, so the wizard also offers the
# include file. Answers: default role (detected: both), keep TLS, accept the
# include, proceed, a bad command, then the real one.
x 'mkdir -p /etc/nftables/conf.d && printf "flush ruleset\ninclude \"/etc/nftables/conf.d/*.nft\"\n" >/etc/nftables.conf'
x "printf '\\n\\n\\n\\nplait-agent enroll -controller http://x -token nope\\nplait-agent enroll -controller https://localhost:8443 -token $TOKEN -ca-fingerprint $FP\\n' | \
	timeout 300 script -qec $INSTALL /dev/null >/tmp/wizard2.log 2>&1 || true"
check "re-run detects the existing install" x 'grep -q "existing installation was found" /tmp/wizard2.log && grep -q "TLS is currently: generated" /tmp/wizard2.log'
check "bad enrollment command explained" x 'grep -q "Could not use that command" /tmp/wizard2.log'
check "pasted command enrolls and starts the agent" x 'systemctl is-active -q plait-agent && cmp -s /etc/plait/controller-ca.pem /var/lib/plaitd/tls/ca.pem'
check "wizard offered and set up the include file" x 'grep -q "runs .flush ruleset. whenever" /tmp/wizard2.log && \
	for i in $(seq 30); do grep -q "^table inet plait {" /etc/nftables/conf.d/plait.nft 2>/dev/null && exit 0; sleep 1; done; exit 1'

echo "--- upgrades keep the controller's name"
SAN="echo | openssl s_client -connect localhost:8443 2>/dev/null | openssl x509 -noout -ext subjectAltName"
names_kept() { x 'tr -d "\n " </etc/plait/plaitd.json | grep -q "\"tls_names\":\[\"plait.test\"\]"'; }
check "re-run with --tls-auto" x "$INSTALL controller --tls-auto >/tmp/up1.log 2>&1"
check "tls_names kept" names_kept
check "certificate still covers plait.test" x "for i in \$(seq 30); do $SAN | grep -q DNS:plait.test && exit 0; sleep 1; done; exit 1"
check "upgrade prints the web UI at plait.test" x 'grep -q "web UI: https://plait.test:8443/" /tmp/up1.log'
# Answers: default role, change TLS, generated, accept the offered name, proceed.
x "printf '\\ny\\n1\\n\\n\\n' | timeout 300 script -qec $INSTALL /dev/null >/tmp/wizard3.log 2>&1 || true"
check "wizard offers the saved name, not the local one" x 'grep -q "reach this controller \[plait.test\]" /tmp/wizard3.log'
check "wizard re-run keeps tls_names" names_kept
check "certificate covers plait.test after the wizard" x "$SAN | grep -q DNS:plait.test"

echo "--- uninstall, reinstall, purge"
x 'for i in $(seq 30); do [ -d /sys/class/net/plait0 ] && exit 0; sleep 1; done'
# The host config now forwards plait*, as a host firewall tool would write it.
x 'printf "table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\tiifname \"plait*\" accept\n\t}\n}\n" >>/etc/nftables.conf && nft -c -f /etc/nftables.conf'
check "--uninstall finds both roles" x "$INSTALL --uninstall >/tmp/un.log 2>&1 && grep -q 'removing the gateway agent' /tmp/un.log && grep -q 'removing the controller' /tmp/un.log"
check "services, units, and binaries gone" x '! systemctl is-active -q plaitd && ! systemctl is-active -q plait-agent && \
	[ ! -e /etc/systemd/system/plaitd.service ] && [ ! -e /etc/systemd/system/plait-agent.service ] && \
	[ ! -e /etc/systemd/system/plait-agent.service.d ] && [ ! -e /usr/local/bin/plaitd ] && [ ! -e /usr/local/bin/plaitctl ] && [ ! -e /usr/local/bin/plait-agent ]'
check "plait0, table, and include file gone" x '[ ! -e /sys/class/net/plait0 ] && ! nft list table inet plait 2>/dev/null && [ ! -e /etc/nftables/conf.d/plait.nft ]'
check "host settings and docs gone" x '[ ! -e /etc/sysctl.d/90-plait.conf ] && [ ! -e /etc/modules-load.d/plait.conf ] && [ ! -e /usr/share/doc/plait ]'
check "config, keys, data, and user kept" x '[ -f /etc/plait/plaitd.json ] && [ -f /etc/plait/psk.key ] && [ -f /var/lib/plaitd/plaitd.db ] && \
	[ -f /etc/plait/agent.json ] && [ -n "$(ls /var/lib/plait)" ] && getent passwd plaitd >/dev/null'
check "says how to clean up the host firewall" x "grep -q 'remove Plait.s lines from /etc/nftables.conf' /tmp/un.log"
check "reinstall resumes both roles" x "$INSTALL controller agent >/dev/null && systemctl is-active -q plaitd && systemctl is-active -q plait-agent && \
	[ \"\$(runuser -u plaitd -- plaitctl admin count)\" = 1 ] && runuser -u plaitd -- plaitctl tls status | grep -qx 'ca_fingerprint: $FP'"
check "agent reapplies after reinstall" x 'for i in $(seq 30); do grep -q "^table inet plait {" /etc/nftables/conf.d/plait.nft 2>/dev/null && [ -d /sys/class/net/plait0 ] && exit 0; sleep 1; done; exit 1'
check "interactive purge defaults to no" x "printf '\\n' | script -qec '$INSTALL --purge' /dev/null >/tmp/purge0.log; \
	grep -q 'permanently delete' /tmp/purge0.log && grep -q 'Nothing was changed' /tmp/purge0.log && systemctl is-active -q plaitd && [ -f /etc/plait/psk.key ]"
check "--purge agent removes only the gateway" x "$INSTALL --purge agent >/dev/null && [ ! -e /var/lib/plait ] && [ ! -e /etc/plait/agent.json ] && \
	[ ! -e /etc/plait/controller-ca.pem ] && systemctl is-active -q plaitd && [ -e /usr/share/doc/plait ]"
check "--purge removes everything" x "$INSTALL --purge >/dev/null && [ ! -e /etc/plait ] && [ ! -e /var/lib/plaitd ] && [ ! -e /var/backups/plaitd ] && \
	! getent passwd plaitd && ! getent group plaitd && [ ! -e /usr/share/doc/plait ] && [ ! -e /usr/local/bin/plaitd ]"
check "nothing left to remove" x "$INSTALL --uninstall | grep -q 'not installed'"

echo "--- $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
