#!/bin/sh
# Install or upgrade Plait on a Linux host (Debian trixie is the primary
# target). Safe to re-run: it converges users, directories, permissions,
# dependencies, binaries, and systemd units, and restarts services only when
# something they depend on changed. It never overwrites existing
# configuration, keys, or state.
#
#   sudo ./install.sh                 guided setup (asks everything)
#   sudo ./install.sh [options] controller|agent [controller|agent]
#   sudo ./install.sh --uninstall [--purge] [controller|agent ...]
#
# See docs/deploy.md for what to do before and after.
set -eu

usage() {
	cat <<'EOF'
usage: install.sh                    guided setup from a terminal
       install.sh [options] ROLE...    for scripts and automation
       install.sh --uninstall [--purge] [ROLE...]

Roles:
  controller   plaitd + plaitctl, the plaitd system user, /var/lib/plaitd
  agent        plait-agent, nftables, kernel WireGuard, IPv4 forwarding

Options:
  --bin-dir DIR        directory holding the Linux binaries (default: a local
                       build in bin/linux-<arch>, else prebuilt dist/linux-<arch>)
  --client-pool CIDR   controller: device address pool for a new config
                       (asked interactively when omitted)
  --listen ADDR        controller: listen address for a new config
                       (default 0.0.0.0:8443)

TLS for the controller (default for a new install: generated automatically,
or a choice when Let's Encrypt certificates exist and a terminal is present;
an existing install keeps its setting unless one of these is given):
  --tls-auto           plaitd generates and renews its own certificate and CA
  --tls-name NAME      auto: an extra DNS name or IP for the certificate, e.g.
                       a public name behind NAT (repeatable; the host's own
                       names and addresses are always included). Replaces the
                       saved names; without it, an upgrade keeps them
  --controller-name NAME
                       the name gateways and browsers use to reach the
                       controller, e.g. wg.example.net under a wildcard
                       certificate; checked against the certificate and
                       kept for later upgrades (default: the saved name)
  --letsencrypt[=NAME] use /etc/letsencrypt/live/NAME (asked when several
                       exist) and install a certbot renewal hook
  --tls-cert FILE      use this certificate chain ...
  --tls-key FILE       ... and key (copied to /etc/plait/tls)

Gateway firewall integration (for hosts whose nftables configuration is
managed elsewhere and runs 'flush ruleset' on reload):
  --nft-include[=PATH] keep a copy of Plait's table at PATH for that
                       configuration to include (default
                       /etc/nftables/conf.d/plait.nft; offered automatically)
  --no-nft-include     stop maintaining the include file

  --no-deps            do not install distribution packages
  --no-start           install only; do not enable, start, or restart services
  -h, --help           show this help

Removal (the named roles, else every role found on this host; asks first
when run from a terminal, unless PLAIT_NONINTERACTIVE=1):
  --uninstall          stop and remove services, binaries, units, the gateway's
                       interface and firewall table, and host settings; keep
                       configuration, keys, the database, and backups, so a
                       later install resumes where it left off
  --purge              --uninstall, and also delete configuration, keys, the
                       database, backups, gateway state, and the plaitd user
                       (irreversible: back up first with plaitctl backup)
EOF
}

say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

PREFIX=/usr/local/bin
ETC=/etc/plait
UNIT_DIR=/etc/systemd/system
DOC_DIR=/usr/share/doc/plait
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")

BIN_DIR='' CLIENT_POOL='' LISTEN=0.0.0.0:8443 TLS_CERT='' TLS_KEY=''
TLS_AUTO=0 TLS_NAMES='' TLS_NAMES_SET=0 LE=0 LE_NAME=''
NFT_INCLUDE_DEFAULT=/etc/nftables/conf.d/plait.nft NFT_INCLUDE='' NFT_INCLUDE_SET=0
DEPS=1 START=1 DO_CONTROLLER=0 DO_AGENT=0 WIZARD=0 CONTROLLER_NAME=''
UNINSTALL=0 PURGE=0
while [ $# -gt 0 ]; do
	case $1 in
	--bin-dir) BIN_DIR=${2:?}; shift ;;
	--client-pool) CLIENT_POOL=${2:?}; shift ;;
	--listen) LISTEN=${2:?}; shift ;;
	--tls-cert) TLS_CERT=${2:?}; shift ;;
	--tls-key) TLS_KEY=${2:?}; shift ;;
	--tls-auto) TLS_AUTO=1 ;;
	--tls-name)
		case ${2:?} in *[!A-Za-z0-9.:-]* | '') die "invalid --tls-name: $2" ;; esac
		TLS_NAMES="$TLS_NAMES $2" TLS_NAMES_SET=1; shift ;;
	--controller-name)
		case ${2:?} in *[!A-Za-z0-9.:-]* | '') die "invalid --controller-name: $2" ;; esac
		CONTROLLER_NAME=$2; shift ;;
	--letsencrypt) LE=1 ;;
	--letsencrypt=*) LE=1 LE_NAME=${1#--letsencrypt=} ;;
	--nft-include) NFT_INCLUDE=$NFT_INCLUDE_DEFAULT NFT_INCLUDE_SET=1 ;;
	--nft-include=*) NFT_INCLUDE=${1#--nft-include=} NFT_INCLUDE_SET=1 ;;
	--no-nft-include) NFT_INCLUDE='' NFT_INCLUDE_SET=1 ;;
	--no-deps) DEPS=0 ;;
	--no-start) START=0 ;;
	--uninstall) UNINSTALL=1 ;;
	--purge) UNINSTALL=1 PURGE=1 ;;
	controller) DO_CONTROLLER=1 ;;
	agent) DO_AGENT=1 ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
	shift
done
if [ $UNINSTALL = 1 ]; then
	: # roles are optional; uninstall finds what is installed
elif [ $DO_CONTROLLER = 0 ] && [ $DO_AGENT = 0 ]; then
	# No role: walk through the setup when someone is at a terminal.
	if [ "${PLAIT_NONINTERACTIVE:-0}" != 1 ] && (: </dev/tty) 2>/dev/null; then
		WIZARD=1
	else
		usage >&2
		die "name at least one role (or run from a terminal for a guided setup)"
	fi
fi
if [ -n "$TLS_CERT" ] && [ -z "$TLS_KEY" ] || [ -z "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
	die "--tls-cert and --tls-key go together"
fi
[ -z "$TLS_NAMES" ] || TLS_AUTO=1
case $NFT_INCLUDE in '' | /*.nft) ;; *) die "--nft-include needs an absolute path ending in .nft" ;; esac
if [ $((TLS_AUTO + LE + $([ -n "$TLS_CERT" ] && echo 1 || echo 0))) -gt 1 ]; then
	die "choose one of --tls-auto/--tls-name, --letsencrypt, --tls-cert"
fi

[ "$(id -u)" = 0 ] || die "run as root"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required"
if [ -r /etc/os-release ]; then
	. /etc/os-release
	[ "${ID:-}" = debian ] || warn "tested on Debian; continuing on ${PRETTY_NAME:-unknown}"
fi

# --- binaries ---------------------------------------------------------------

case $(uname -m) in
x86_64) GOARCH=amd64 ELF=3e00 ;;
aarch64) GOARCH=arm64 ELF=b700 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
if [ -z "$BIN_DIR" ] && [ $UNINSTALL = 0 ]; then
	for d in "$ROOT/bin/linux-$GOARCH" "$ROOT/dist/linux-$GOARCH" "$ROOT/dist" "$HERE"; do
		[ -x "$d/plaitd" ] || [ -x "$d/plait-agent" ] && { BIN_DIR=$d; break; }
	done
	[ -n "$BIN_DIR" ] || die "no binaries found; build with: GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 go build -o dist/ ./cmd/...  (or pass --bin-dir)"
fi

need_bin() {
	f=$BIN_DIR/$1
	[ -f "$f" ] && [ -x "$f" ] || die "missing $f"
	# ELF e_machine (little-endian) must match this host.
	m=$(od -An -tx1 -j18 -N2 "$f" | tr -d ' \n')
	[ "$m" = "$ELF" ] || die "$f is not a linux/$GOARCH binary"
	# Prebuilt binaries ship with dist/SHA256SUMS; verify when present.
	sums=$(dirname "$BIN_DIR")/SHA256SUMS
	if [ -f "$sums" ]; then
		want=$(awk -v n="$(basename "$BIN_DIR")/$1" '$2 == n { print $1 }' "$sums")
		[ -n "$want" ] || die "$1 is not listed in $sums"
		[ "$(sha256sum "$f" | cut -d' ' -f1)" = "$want" ] || die "$f does not match $sums"
	fi
}

# install_file SRC DST MODE: atomic replace; sets INSTALLED=1 if it changed
# anything. Binaries keep the previous version as DST.prev.
install_file() {
	INSTALLED=0
	if [ -f "$2" ] && cmp -s "$1" "$2"; then
		return 0
	fi
	install -m "$3" -o root -g root "$1" "$2.plait-new"
	if [ -f "$2" ] && [ "${2#"$PREFIX"/}" != "$2" ]; then
		cp -p "$2" "$2.prev"
	fi
	mv -f "$2.plait-new" "$2"
	INSTALLED=1
}

# --- dependencies -----------------------------------------------------------

missing_pkgs() {
	for p in "$@"; do
		dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || printf '%s ' "$p"
	done
}

install_pkgs() {
	[ $DEPS = 1 ] || return 0
	command -v apt-get >/dev/null || { warn "no apt-get; install manually: $*"; return 0; }
	m=$(missing_pkgs "$@")
	[ -n "$m" ] || return 0
	say "installing packages: $m"
	export DEBIAN_FRONTEND=noninteractive
	# shellcheck disable=SC2086
	# No stdin: nothing here should ever read the user's terminal.
	apt-get update -q </dev/null && apt-get install -y -q --no-install-recommends $m </dev/null
}

install_docs() {
	install -d -m 0755 "$DOC_DIR"
	for f in agent controller deploy ui; do
		[ -f "$ROOT/docs/$f.md" ] && install -m 0644 "$ROOT/docs/$f.md" "$DOC_DIR/$f.md"
	done
	return 0
}

# json_get FILE KEY: the string value of a top-level key (no jq needed for
# the flat configs Plait writes).
json_get() {
	sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -n1
}

# saved_names CONFIG: the names an existing controller is reached by beyond
# the host's own, one per line, most specific first: the recorded controller
# name, its tls_names (on one line or several), and the Let's Encrypt
# certificate name when it uses one. Names hold no quotes or commas.
saved_names() {
	[ -f "$1" ] || return 0
	{
		[ ! -f "$NAME_FILE" ] || cat "$NAME_FILE"
		tr -d '\n' <"$1" | sed -n 's/.*"tls_names"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d ' \t"' | tr ',' '\n'
		[ ! -f "$LE_MARK" ] || cat "$LE_MARK"
	} | awk 'NF && !seen[$0]++'
}

# check_name_covered CONFIG: warn when plaitd serves certificate files that
# do not cover the controller's name.
check_name_covered() {
	cert=$(json_get "$1" tls_cert_file)
	name=$(saved_names "$1" | head -n1)
	[ -n "$cert" ] && [ -f "$cert" ] && [ -n "$name" ] && command -v openssl >/dev/null || return 0
	openssl x509 -noout -checkhost "$name" -in "$cert" 2>/dev/null | grep -q 'does match' ||
		warn "$cert does not cover $name; gateways and browsers using that name will reject it"
}

UNITS_CHANGED=0
install_unit() {
	[ -f "$HERE/$1" ] || die "missing $HERE/$1"
	install_file "$HERE/$1" "$UNIT_DIR/$1" 0644
	if [ $INSTALLED = 1 ]; then
		UNITS_CHANGED=1
		eval "CHANGED_$2=1"
	fi
}

# converge SERVICE CHANGED: enable, then start or restart as needed.
converge() {
	[ $START = 1 ] || { say "--no-start: leaving $1 as is"; return 0; }
	systemctl enable -q "$1"
	if ! systemctl is-active -q "$1"; then
		say "starting $1"
		systemctl start "$1"
	elif [ "$2" = 1 ]; then
		say "restarting $1"
		systemctl restart "$1"
	else
		say "$1 unchanged and running"
	fi
	sleep 2
	systemctl is-active -q "$1" || die "$1 failed to start; see: journalctl -u $1 -n 50"
}

NEXT=""
next() { NEXT="$NEXT
  - $*"; }

# interactive: a terminal is available for questions (also under curl | sh).
interactive() {
	[ "${PLAIT_NONINTERACTIVE:-0}" != 1 ] && (: </dev/tty) 2>/dev/null
}

# ask PROMPT DEFAULT: sets REPLY.
ask() {
	printf '%s [%s]: ' "$1" "$2" >/dev/tty
	read -r REPLY </dev/tty || REPLY=''
	[ -n "$REPLY" ] || REPLY=$2
}

# yes_no QUESTION DEFAULT(y|n): succeeds for yes.
yes_no() {
	while :; do
		ask "$1 (y/n)" "$2"
		case $REPLY in [Yy]*) return 0 ;; [Nn]*) return 1 ;; esac
	done
}

# menu TITLE ITEM...: sets REPLY to the chosen item's number (default
# $MENU_DEFAULT, else 1).
menu() {
	printf '%s\n' "$1" >/dev/tty
	shift
	i=0
	for item in "$@"; do
		i=$((i + 1))
		printf '  %d) %s\n' "$i" "$item" >/dev/tty
	done
	while :; do
		ask "choose 1-$i" "${MENU_DEFAULT:-1}"
		case $REPLY in '' | *[!0-9]*) continue ;; esac
		[ "$REPLY" -ge 1 ] && [ "$REPLY" -le "$i" ] && { MENU_DEFAULT=''; return 0; }
	done
}

is_loopback() {
	case $1 in 127.* | localhost:* | "[::1]:"*) return 0 ;; esac
	return 1
}

# --- controller TLS ---------------------------------------------------------

LE_LIVE=/etc/letsencrypt/live
LE_HOOK=/etc/letsencrypt/renewal-hooks/deploy/plait
LE_MARK=$ETC/tls/letsencrypt-lineage
NAME_FILE=$ETC/controller-name

le_lineages() {
	[ -d "$LE_LIVE" ] || return 0
	for d in "$LE_LIVE"/*/; do
		[ -f "${d}fullchain.pem" ] && [ -f "${d}privkey.pem" ] && basename "$d"
	done
	return 0
}

# pick_lineage: sets LE_NAME for --letsencrypt without a name.
pick_lineage() {
	lineages=$(le_lineages)
	case $(printf '%s' "$lineages" | grep -c .) in
	0) die "no certificates found in $LE_LIVE" ;;
	1) LE_NAME=$lineages ;;
	*)
		interactive || die "several Let's Encrypt certificates ($(echo $lineages)); choose with --letsencrypt=NAME"
		# shellcheck disable=SC2086
		menu "Let's Encrypt certificate for plaitd:" $lineages
		LE_NAME=$(printf '%s\n' "$lineages" | sed -n "${REPLY}p")
		;;
	esac
}

# decide_tls CONFIG: sets TLS_MODE to keep, auto, off, files, or le.
decide_tls() {
	if [ -n "$TLS_CERT" ]; then
		TLS_MODE=files
	elif [ $LE = 1 ]; then
		TLS_MODE=le
		[ -n "$LE_NAME" ] || pick_lineage
	elif [ $TLS_AUTO = 1 ]; then
		TLS_MODE=auto
	elif [ -f "$1" ]; then
		TLS_MODE=keep
	elif is_loopback "$LISTEN"; then
		TLS_MODE=off
	elif [ -n "$(le_lineages)" ] && interactive; then
		lineages=$(le_lineages)
		set -- "generate and renew one automatically (no setup)"
		for n in $lineages; do set -- "$@" "Let's Encrypt: $n"; done
		menu "TLS certificate for plaitd:" "$@"
		if [ "$REPLY" = 1 ]; then
			TLS_MODE=auto
		else
			TLS_MODE=le
			LE_NAME=$(printf '%s\n' "$lineages" | sed -n "$((REPLY - 1))p")
		fi
	else
		TLS_MODE=auto
		[ -z "$(le_lineages)" ] || say "Let's Encrypt certificates exist; using a generated certificate (re-run with --letsencrypt to use one)"
	fi
}

# copy_tls CERT KEY: install a certificate pair where plaitd reads it. plaitd
# reloads replaced files itself, so this never requires a restart.
copy_tls() {
	install -m 0644 -o root -g plaitd "$1" "$ETC/tls/cert.pem.plait-new"
	install -m 0600 -o plaitd -g plaitd "$2" "$ETC/tls/key.pem.plait-new"
	mv -f "$ETC/tls/key.pem.plait-new" "$ETC/tls/key.pem"
	mv -f "$ETC/tls/cert.pem.plait-new" "$ETC/tls/cert.pem"
}

install_le_hook() {
	install -d -m 0755 "$(dirname "$LE_HOOK")"
	cat >"$LE_HOOK.tmp" <<EOF
#!/bin/sh
# Installed by Plait's install.sh. certbot runs this after each renewal; it
# copies the renewed certificate to where plaitd reads it, and plaitd picks
# it up within a minute without restarting.
set -eu
[ "\${RENEWED_LINEAGE:-}" = "$LE_LIVE/$1" ] || exit 0
install -m 0644 -o root -g plaitd "\$RENEWED_LINEAGE/fullchain.pem" $ETC/tls/cert.pem.plait-new
install -m 0600 -o plaitd -g plaitd "\$RENEWED_LINEAGE/privkey.pem" $ETC/tls/key.pem.plait-new
mv -f $ETC/tls/key.pem.plait-new $ETC/tls/key.pem
mv -f $ETC/tls/cert.pem.plait-new $ETC/tls/cert.pem
EOF
	install_file "$LE_HOOK.tmp" "$LE_HOOK" 0755
	rm -f "$LE_HOOK.tmp"
	printf '%s\n' "$1" >"$LE_MARK"
}

remove_le_hook() {
	if [ -f "$LE_MARK" ] || [ -f "$LE_HOOK" ]; then
		say "removing the Let's Encrypt renewal hook"
		rm -f "$LE_HOOK" "$LE_MARK"
	fi
}

# apply_tls CONFIG: put certificate files in place and record the mode in
# the configuration. Sets CONFIG_CHANGED when the configuration changed.
apply_tls() {
	# A switch to (or re-run of) generated TLS without explicit names keeps
	# the names gateways and browsers already use; dropping them would
	# reissue the certificate for this host's local names only.
	if [ "$TLS_MODE" = auto ] && [ $TLS_NAMES_SET = 0 ]; then
		TLS_NAMES=$(saved_names "$1" | tr '\n' ' ')
	fi
	case $TLS_MODE in
	files)
		copy_tls "$TLS_CERT" "$TLS_KEY"
		remove_le_hook
		;;
	le)
		[ -f "$LE_LIVE/$LE_NAME/fullchain.pem" ] || die "no certificate at $LE_LIVE/$LE_NAME"
		say "using Let's Encrypt certificate $LE_NAME"
		copy_tls "$LE_LIVE/$LE_NAME/fullchain.pem" "$LE_LIVE/$LE_NAME/privkey.pem"
		install_le_hook "$LE_NAME"
		;;
	auto | off)
		remove_le_hook
		;;
	keep)
		# Re-sync a Let's Encrypt certificate in case a renewal hook was missed.
		if [ -f "$LE_MARK" ]; then
			LE_NAME=$(cat "$LE_MARK")
			if [ -f "$LE_LIVE/$LE_NAME/fullchain.pem" ]; then
				cmp -s "$LE_LIVE/$LE_NAME/fullchain.pem" "$ETC/tls/cert.pem" ||
					copy_tls "$LE_LIVE/$LE_NAME/fullchain.pem" "$LE_LIVE/$LE_NAME/privkey.pem"
				install_le_hook "$LE_NAME"
			else
				warn "Let's Encrypt certificate $LE_NAME is gone; plaitd keeps serving its last copy"
			fi
		fi
		;;
	esac
	CONFIG_CHANGED=0
	[ -f "$1" ] && [ "$TLS_MODE" != keep ] && [ "$TLS_MODE" != off ] || return 0
	cp -p "$1" "$1.plait-old"
	case $TLS_MODE in
	files | le) set -- "$1" files -cert "$ETC/tls/cert.pem" -key "$ETC/tls/key.pem" ;;
	*)
		set -- "$1" auto
		for n in $TLS_NAMES; do set -- "$@" -name "$n"; done
		;;
	esac
	cfgfile=$1
	shift
	out=$(PLAIT_CONFIG=$cfgfile "$PREFIX/plaitctl" tls "$@" 2>&1) || { mv -f "$cfgfile.plait-old" "$cfgfile"; die "$out"; }
	set -- "$cfgfile"
	cmp -s "$1" "$1.plait-old" || { CONFIG_CHANGED=1; say "TLS mode set to $TLS_MODE in $1"; }
	rm -f "$1.plait-old"
}

# tls_json: the TLS fields for a new configuration.
tls_json() {
	case $TLS_MODE in
	files | le) printf ',\n  "tls_cert_file": "%s",\n  "tls_key_file": "%s"' "$ETC/tls/cert.pem" "$ETC/tls/key.pem" ;;
	auto)
		[ -n "$TLS_NAMES" ] || return 0
		printf ',\n  "tls_names": ['
		sep=''
		for n in $TLS_NAMES; do printf '%s"%s"' "$sep" "$n"; sep=', '; done
		printf ']'
		;;
	esac
}

# --- guided setup -----------------------------------------------------------

tell() { printf '%s\n' "$@" >/dev/tty; }

# ask_controller_name DEFAULT: sets CONTROLLER_NAME.
ask_controller_name() {
	while :; do
		ask "Name or address used to reach this controller" "$1"
		case $REPLY in *[!A-Za-z0-9.:-]*) tell "letters, digits, dots, colons and hyphens only" ;; *) break ;; esac
	done
	CONTROLLER_NAME=$REPLY
}

wizard_tls() {
	lineages=$(le_lineages)
	set -- "Generate a certificate automatically (nothing to manage)"
	for n in $lineages; do set -- "$@" "Let's Encrypt: $n"; done
	set -- "$@" "Use my own certificate files"
	menu "How should the controller handle TLS?" "$@"
	nle=$(printf '%s' "$lineages" | grep -c . || true)
	local_name=$(hostname -f 2>/dev/null || hostname)
	saved=$(saved_names "$ETC/plaitd.json" | tr '\n' ' ')
	saved_first=${saved%% *}
	if [ "$REPLY" = 1 ]; then
		TLS_AUTO=1
		tell "" "The certificate covers this host's names and addresses. If gateways or" \
			"browsers reach it by another name (e.g. a public DNS name behind NAT)," \
			"enter that; otherwise keep the default."
		def=${saved_first:-$local_name}
		ask_controller_name "$def"
		TLS_NAMES_SET=1
		if [ "$REPLY" = "$local_name" ]; then
			TLS_NAMES=''
		elif [ "$REPLY" = "$def" ]; then
			TLS_NAMES=" $saved"
		else
			TLS_NAMES=" $REPLY"
		fi
	elif [ "$REPLY" -le $((nle + 1)) ]; then
		LE=1
		LE_NAME=$(printf '%s\n' "$lineages" | sed -n "$((REPLY - 1))p")
		tell "" "For a wildcard certificate, enter the full name, e.g. wg.$LE_NAME."
		ask_controller_name "${saved_first:-$LE_NAME}"
	else
		while :; do
			ask "Certificate chain file (PEM)" "/etc/ssl/certs/plait.pem"
			TLS_CERT=$REPLY
			ask "Private key file (PEM)" "/etc/ssl/private/plait.key"
			TLS_KEY=$REPLY
			[ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] && break
			tell "Both files must exist."
		done
		ask_controller_name "${saved_first:-$local_name}"
	fi
}

wizard() {
	tell "" "Plait installer" "==============="
	have_ctl=0 have_agent=0
	[ -f "$ETC/plaitd.json" ] && have_ctl=1
	[ -f "$ETC/agent.json" ] && have_agent=1
	if [ $have_ctl = 1 ] || [ $have_agent = 1 ]; then
		tell "An existing installation was found. This upgrades it and keeps its settings."
	fi
	tell ""
	MENU_DEFAULT=1
	[ $have_agent = 1 ] && MENU_DEFAULT=2
	[ $have_ctl = 1 ] && [ $have_agent = 1 ] && MENU_DEFAULT=3
	menu "What should this host run?" \
		"Controller: web UI and API (one per deployment)" \
		"Gateway for a site: connects devices to that site's LAN" \
		"Both"
	case $REPLY in 1) DO_CONTROLLER=1 ;; 2) DO_AGENT=1 ;; 3) DO_CONTROLLER=1 DO_AGENT=1 ;; esac

	plan=""
	if [ $DO_CONTROLLER = 1 ]; then
		tell ""
		if [ $have_ctl = 0 ]; then
			tell "Devices get tunnel addresses from a pool that must not overlap any site LAN" \
				"or networks your users join (home Wi-Fi, hotels, carrier NAT)."
			ask "Client address pool" 10.99.0.0/24
			CLIENT_POOL=$REPLY
			while :; do
				ask "Port for the web UI and gateways (TCP)" 8443
				case $REPLY in '' | *[!0-9]*) continue ;; esac
				[ "$REPLY" -ge 1024 ] && [ "$REPLY" -le 65535 ] && break
				tell "use a port from 1024 to 65535 (the service cannot bind lower ports)"
			done
			LISTEN=0.0.0.0:$REPLY
			tell ""
			wizard_tls
		else
			mode=generated
			[ -n "$(json_get "$ETC/plaitd.json" tls_cert_file)" ] && mode="certificate files"
			[ -f "$LE_MARK" ] && mode="Let's Encrypt ($(cat "$LE_MARK"))"
			is_loopback "$(json_get "$ETC/plaitd.json" listen)" && mode="reverse proxy"
			tell "TLS is currently: $mode"
			if yes_no "Change TLS settings?" n; then
				wizard_tls
			fi
		fi
		tls_desc="keep current"
		[ $TLS_AUTO = 1 ] && tls_desc="generated automatically${TLS_NAMES:+, also covering$TLS_NAMES}"
		[ $LE = 1 ] && tls_desc="Let's Encrypt certificate $LE_NAME (renewals picked up automatically)"
		[ -n "$TLS_CERT" ] && tls_desc="$TLS_CERT"
		if [ $have_ctl = 0 ]; then
			plan="$plan
  controller: pool $CLIENT_POOL, listening on $LISTEN, TLS: $tls_desc"
		else
			plan="$plan
  controller: upgrade, TLS: $tls_desc"
		fi
	fi
	if [ $DO_AGENT = 1 ] && [ $NFT_INCLUDE_SET = 0 ] && host_nft_flushes &&
		[ -z "$(json_get "$ETC/agent.json" nft_include_file 2>/dev/null)" ]; then
		tell "" "$HOST_NFT runs 'flush ruleset' whenever it is reloaded, which removes Plait's" \
			"firewall table until the agent restores it (up to ~15 s). Plait can keep a copy" \
			"of its table in a file for that configuration to include, so reloads keep it."
		if yes_no "Write Plait's table to $NFT_INCLUDE_DEFAULT for your configuration to include?" y; then
			NFT_INCLUDE=$NFT_INCLUDE_DEFAULT NFT_INCLUDE_SET=1
		fi
	fi
	if [ $DO_AGENT = 1 ]; then
		plan="$plan
  gateway: plait-agent, nftables, WireGuard, IPv4 forwarding"
		[ -z "$NFT_INCLUDE" ] || plan="$plan
           Plait's nftables table also kept in $NFT_INCLUDE"
		[ $have_agent = 1 ] && plan="$plan (upgrade)"
	fi
	tell "" "This will install:$plan" ""
	yes_no "Proceed?" y || { tell "Nothing was changed."; exit 0; }
}

# wizard_admin CONFIG: offer to create the first administrator.
wizard_admin() {
	n=$(runuser -u plaitd -- env PLAIT_CONFIG="$1" "$PREFIX/plaitctl" admin count 2>/dev/null || echo 1)
	[ "$n" = 0 ] || return 0
	if [ $WIZARD = 1 ] && yes_no "Create the first administrator for the web UI now?" y; then
		for _ in 1 2 3; do
			while :; do
				ask "Username" admin
				case $REPLY in *[!A-Za-z0-9._-]* | '') tell "letters, digits, dot, underscore, hyphen" ;; *) break ;; esac
			done
			if runuser -u plaitd -- env PLAIT_CONFIG="$1" "$PREFIX/plaitctl" admin create "$REPLY" </dev/tty; then
				return 0
			fi
		done
	fi
	next "create an administrator: runuser -u plaitd -- plaitctl admin create <name>"
}

# wizard_enroll: enroll this gateway from the command shown on a site page.
wizard_enroll() {
	tell "" "This gateway is not enrolled yet. In the web UI open Sites, choose the site" \
		"(or add it), click \"Issue enrollment token\", and paste the command shown."
	for _ in 1 2 3; do
		ask "Enrollment command (Enter to skip)" ""
		[ -n "$REPLY" ] || return 0
		set -f
		# shellcheck disable=SC2086
		set -- $REPLY
		set +f
		[ "${1:-}" = plait-agent ] && shift
		[ "${1:-}" = enroll ] && shift
		ctl='' tok='' fp='' bad=''
		while [ $# -gt 0 ]; do
			case $1 in
			-controller | --controller) ctl=${2:-}; shift ;;
			-token | --token) tok=${2:-}; shift ;;
			-ca-fingerprint | --ca-fingerprint) fp=${2:-}; shift ;;
			*) bad="unexpected \"$1\"" ;;
			esac
			shift
		done
		host=$(printf '%s' "${ctl#https://}" | tr -d '[]/')
		case $ctl in https://*) ;; *) bad="the controller URL must start with https://" ;; esac
		case $host in '' | *[!A-Za-z0-9.:-]*) bad="invalid controller URL" ;; esac
		case $tok in plaite_*) case ${tok#plaite_} in '' | *[!A-Za-z0-9_-]*) bad="invalid token" ;; esac ;; *) bad="missing or invalid -token" ;; esac
		if [ -n "$fp" ]; then
			hex=${fp#sha256:}
			case $hex in *[!0-9a-fA-F]*) bad="invalid -ca-fingerprint" ;; esac
			[ "$fp" != "$hex" ] && [ ${#hex} = 64 ] || bad="invalid -ca-fingerprint"
		fi
		if [ -n "$bad" ]; then
			tell "Could not use that command: $bad"
			continue
		fi
		set -- enroll -controller "$ctl" -token "$tok"
		[ -z "$fp" ] || set -- "$@" -ca-fingerprint "$fp"
		if "$PREFIX/plait-agent" "$@"; then
			return 0
		fi
		tell "Enrollment failed (see above). An unused token can be tried again; otherwise issue a new one."
	done
}

# --- controller -------------------------------------------------------------

controller() {
	say "controller"
	need_bin plaitd
	need_bin plaitctl
	CHANGED_plaitd=0
	cfg=$ETC/plaitd.json

	if ! getent passwd plaitd >/dev/null; then
		say "creating system user plaitd"
		useradd --system --user-group --home-dir /var/lib/plaitd --no-create-home \
			--shell /usr/sbin/nologin --comment "Plait controller" plaitd
	fi
	install -d -m 0755 -o root -g root "$ETC"
	install -d -m 0750 -o root -g plaitd "$ETC/tls"
	install -d -m 0700 -o plaitd -g plaitd /var/lib/plaitd /var/backups/plaitd
	# Repair ownership: a plaitctl run as root may have created database files.
	chown -R plaitd:plaitd /var/lib/plaitd

	# Upgrade: back up with the old binaries, then stop before migrations run.
	was_active=0
	systemctl is-active -q plaitd && was_active=1
	upgrading=0
	if [ -x "$PREFIX/plaitd" ] && ! cmp -s "$BIN_DIR/plaitd" "$PREFIX/plaitd"; then
		upgrading=1
	fi
	db=/var/lib/plaitd/plaitd.db
	[ -f "$cfg" ] && [ -n "$(json_get "$cfg" database)" ] && db=$(json_get "$cfg" database)
	if [ $upgrading = 1 ] && [ -f "$cfg" ] && [ -f "$db" ]; then
		bk=/var/backups/plaitd/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ).db
		say "backing up database to $bk"
		runuser -u plaitd -- env PLAIT_CONFIG="$cfg" "$PREFIX/plaitctl" backup "$bk" 2>/dev/null ||
			die "pre-upgrade backup failed; nothing was changed"
		if [ $was_active = 1 ] && [ $START = 1 ]; then
			say "stopping plaitd for upgrade"
			systemctl stop plaitd
		fi
	fi

	install_file "$BIN_DIR/plaitd" "$PREFIX/plaitd" 0755
	[ $INSTALLED = 0 ] || CHANGED_plaitd=1
	install_file "$BIN_DIR/plaitctl" "$PREFIX/plaitctl" 0755

	if [ ! -f "$cfg" ] && [ -z "$CLIENT_POOL" ] && interactive; then
		printf '%s\n' "Devices get tunnel addresses from a pool that must not overlap any site LAN" \
			"or networks your users join (home Wi-Fi, hotels, carrier NAT)." >/dev/tty
		ask "Client address pool" 10.99.0.0/24
		CLIENT_POOL=$REPLY
	fi
	if [ -n "$CONTROLLER_NAME" ] && [ "$(cat "$NAME_FILE" 2>/dev/null)" != "$CONTROLLER_NAME" ]; then
		say "controller name: $CONTROLLER_NAME"
		printf '%s\n' "$CONTROLLER_NAME" >"$NAME_FILE"
	fi
	decide_tls "$cfg"
	apply_tls "$cfg"
	[ "$CONFIG_CHANGED" = 0 ] || CHANGED_plaitd=1
	[ ! -f "$cfg" ] || check_name_covered "$cfg"

	if [ ! -f "$cfg" ]; then
		if [ -n "$CLIENT_POOL" ]; then
			say "writing $cfg (TLS: $TLS_MODE)"
			tls=$(tls_json)
			umask 022
			cat >"$cfg.plait-new" <<EOF
{
  "database": "/var/lib/plaitd/plaitd.db",
  "encryption_key_file": "$ETC/psk.key",
  "client_pool": "$CLIENT_POOL",
  "listen": "$LISTEN"$tls
}
EOF
			mv -f "$cfg.plait-new" "$cfg"
			CHANGED_plaitd=1
		else
			warn "$cfg does not exist; re-run with --client-pool CIDR (or from a terminal to be asked)"
		fi
	fi

	keyfile=$ETC/psk.key
	[ -f "$cfg" ] && keyfile=$(json_get "$cfg" encryption_key_file)
	[ -n "$keyfile" ] || keyfile=$ETC/psk.key
	if [ ! -e "$keyfile" ]; then
		say "generating PSK encryption key $keyfile"
		"$PREFIX/plaitctl" init-key "$keyfile"
		next "BACK UP $keyfile now, separately from database backups"
	fi
	chown plaitd:plaitd "$keyfile"
	chmod 0600 "$keyfile"
	if [ -f "$cfg" ]; then
		chmod 0644 "$cfg"
		k=$(json_get "$cfg" tls_key_file)
		[ -n "$k" ] && [ -f "$k" ] && { chown plaitd:plaitd "$k"; chmod 0600 "$k"; }
	fi

	install_unit plaitd.service plaitd

	if [ -f "$cfg" ] && [ $START = 1 ]; then
		[ $UNITS_CHANGED = 1 ] && systemctl daemon-reload
		say "checking configuration and stored state"
		if ! runuser -u plaitd -- "$PREFIX/plaitd" -check -config "$cfg"; then
			msg="plaitd -check failed; plaitd is not running"
			[ $upgrading = 1 ] && msg="$msg. To roll back: mv $PREFIX/plaitd.prev $PREFIX/plaitd (and plaitctl.prev), then restore the pre-upgrade backup in /var/backups/plaitd with plaitctl restore"
			die "$msg"
		fi
		converge plaitd "$CHANGED_plaitd"
		wizard_admin "$cfg"
		status=$(runuser -u plaitd -- env PLAIT_CONFIG="$cfg" "$PREFIX/plaitctl" tls status 2>&1 || true)
		printf '%s\n' "$status" | sed 's/^/    /'
		if printf '%s' "$status" | grep -q '^ca_fingerprint:'; then
			next "gateways: copy the enrollment command from each site page; it pins this controller's CA with -ca-fingerprint"
			next "browsers: to avoid certificate warnings, trust https://<this host>:${LISTEN##*:}/ca.pem"
		fi
	fi
	if [ $START = 1 ] && systemctl is-active -q plaitd; then
		port=$(json_get "$cfg" listen)
		port=${port##*:}
		host=$(saved_names "$cfg" | tr '\n' ' ')
		host=${CONTROLLER_NAME:-${host%% *}}
		host=${host:-$(hostname -f 2>/dev/null || hostname)}
		is_loopback "$(json_get "$cfg" listen)" || next "web UI: https://$host:$port/"
	fi
}

# --- agent ------------------------------------------------------------------

HOST_NFT=/etc/nftables.conf
AGENT_PKGS="nftables wireguard-tools ca-certificates kmod procps"
NFT_DROPIN=$UNIT_DIR/plait-agent.service.d/nft-include.conf

# host_nft_flushes: the host's nftables configuration replaces the whole
# ruleset on reload (typical of a configuration managed elsewhere).
host_nft_flushes() {
	grep -qs '^[[:space:]]*flush[[:space:]]\{1,\}ruleset' "$HOST_NFT"
}

# nft_include CONFIG: converge nft_include_file and the unit drop-in that
# lets the sandboxed service write it (ProtectSystem=strict).
nft_include() {
	cur=$(json_get "$1" nft_include_file)
	want=$cur
	[ $NFT_INCLUDE_SET = 0 ] || want=$NFT_INCLUDE
	if [ "$want" != "$cur" ]; then
		[ -z "$want" ] || install -d -m 0755 "$(dirname "$want")"
		out=$("$PREFIX/plait-agent" configure -config "$1" -nft-include "$want" 2>&1) || die "$out"
		CHANGED_agent=1
		if [ -n "$want" ]; then say "Plait's nftables table will be kept in $want"; else say "nft include file disabled"; fi
	fi
	if [ -n "$want" ]; then
		install -d -m 0755 "$(dirname "$NFT_DROPIN")"
		printf '%s\n' "# Installed by Plait's install.sh: lets plait-agent keep its nftables include file." \
			"[Service]" "ReadWritePaths=-$(dirname "$want")" >"$NFT_DROPIN.tmp"
		install_file "$NFT_DROPIN.tmp" "$NFT_DROPIN" 0644
		rm -f "$NFT_DROPIN.tmp"
		if [ $INSTALLED = 1 ]; then UNITS_CHANGED=1 CHANGED_agent=1; fi
		if ! grep -qsF "$(dirname "$want")/" "$HOST_NFT"; then
			next "add to your nftables configuration ($HOST_NFT or the tool that writes it):
      include \"$(dirname "$want")/*.nft\"        (a glob, so hosts without Plait still load)
      forward chain:  iifname \"plait*\" accept   and   oifname \"plait*\" accept
      input chain:    accept the site's UDP port (shown on its site page)"
		fi
	elif [ -f "$NFT_DROPIN" ]; then
		rm -f "$NFT_DROPIN"
		UNITS_CHANGED=1 CHANGED_agent=1
	fi
}

agent() {
	say "agent"
	need_bin plait-agent
	CHANGED_agent=0
	cfg=$ETC/agent.json

	# shellcheck disable=SC2086
	install_pkgs $AGENT_PKGS

	echo wireguard >/etc/modules-load.d/plait.conf.plait-new
	mv -f /etc/modules-load.d/plait.conf.plait-new /etc/modules-load.d/plait.conf
	if [ ! -d /sys/module/wireguard ]; then
		modprobe wireguard 2>/dev/null || warn "could not load the wireguard kernel module"
	fi

	printf 'net.ipv4.ip_forward = 1\n' >/etc/sysctl.d/90-plait.conf
	sysctl -q -p /etc/sysctl.d/90-plait.conf >/dev/null || warn "could not enable net.ipv4.ip_forward"

	install -d -m 0755 -o root -g root "$ETC"
	install -d -m 0700 -o root -g root /var/lib/plait

	nft=$(command -v nft || true)
	[ -n "$nft" ] || nft=/usr/sbin/nft
	if [ ! -f "$cfg" ]; then
		say "writing $cfg"
		umask 022
		cat >"$cfg" <<EOF
{
  "state_dir": "/var/lib/plait",
  "nft_path": "$nft"
}
EOF
	fi
	[ -x "$(json_get "$cfg" nft_path)" ] || warn "nft_path in $cfg is not executable"

	install_file "$BIN_DIR/plait-agent" "$PREFIX/plait-agent" 0755
	[ $INSTALLED = 0 ] || CHANGED_agent=1
	install_unit plait-agent.service agent
	nft_include "$cfg"
	[ $UNITS_CHANGED = 1 ] && systemctl daemon-reload

	if host_nft_flushes && [ -z "$(json_get "$cfg" nft_include_file)" ]; then
		warn "$HOST_NFT runs 'flush ruleset'; each reload removes Plait's table until the agent restores it (up to ~15 s). Re-run with --nft-include to keep it across reloads."
	fi

	if [ -z "$(json_get "$cfg" site_id)" ] && [ $WIZARD = 1 ] && [ $START = 1 ]; then
		wizard_enroll
	fi
	if [ -n "$(json_get "$cfg" site_id)" ]; then
		converge plait-agent "$CHANGED_agent"
	else
		next "enroll this gateway: plait-agent enroll -controller https://CONTROLLER -token plaite_...  then: systemctl enable --now plait-agent"
	fi
}

# --- uninstall --------------------------------------------------------------

controller_present() {
	[ -e "$PREFIX/plaitd" ] || [ -e "$UNIT_DIR/plaitd.service" ] || [ -e "$ETC/plaitd.json" ] ||
		{ [ $PURGE = 1 ] && { [ -d /var/lib/plaitd ] || getent passwd plaitd >/dev/null; }; }
}

agent_present() {
	[ -e "$PREFIX/plait-agent" ] || [ -e "$UNIT_DIR/plait-agent.service" ] || [ -e "$ETC/agent.json" ] ||
		{ [ $PURGE = 1 ] && [ -d /var/lib/plait ]; }
}

uninstall_agent() {
	say "removing the gateway agent"
	cfg=$ETC/agent.json
	systemctl disable --now -q plait-agent 2>/dev/null || true
	if [ -x "$PREFIX/plait-agent" ] && [ -f "$cfg" ]; then
		"$PREFIX/plait-agent" uninstall -config "$cfg" ||
			warn "plait-agent uninstall failed; check for leftovers: ip link show plait0; nft list table inet plait"
	elif [ -e /sys/class/net/plait0 ] || nft list table inet plait >/dev/null 2>&1; then
		warn "cannot run plait-agent uninstall ($PREFIX/plait-agent or $cfg is missing); remove leftovers by hand: ip link del plait0; nft delete table inet plait"
	fi
	rm -f "$UNIT_DIR/plait-agent.service" "$NFT_DROPIN"
	rmdir "$(dirname "$NFT_DROPIN")" 2>/dev/null || true
	rm -f "$PREFIX/plait-agent" "$PREFIX/plait-agent.prev" /etc/modules-load.d/plait.conf /etc/sysctl.d/90-plait.conf
	if [ $PURGE = 1 ]; then
		say "deleting gateway configuration and state (key, credential, cached snapshot)"
		rm -rf /var/lib/plait
		rm -f "$cfg" "$ETC/controller-ca.pem"
	else
		next "kept for a reinstall: $cfg and /var/lib/plait (gateway key, credential, cached state); --purge deletes them"
	fi
	if grep -qs plait "$HOST_NFT"; then
		next "remove Plait's lines from $HOST_NFT (or the tool that writes it): the plait* forward rules, the site's UDP port, and the include"
	fi
	next "net.ipv4.ip_forward keeps its current value until reboot; packages left installed: $AGENT_PKGS"
}

uninstall_controller() {
	say "removing the controller"
	cfg=$ETC/plaitd.json
	port=''
	[ -f "$cfg" ] && port=$(json_get "$cfg" listen) && port=${port##*:}
	systemctl disable --now -q plaitd 2>/dev/null || true
	rm -f "$UNIT_DIR/plaitd.service" "$PREFIX/plaitd" "$PREFIX/plaitd.prev" "$PREFIX/plaitctl" "$PREFIX/plaitctl.prev"
	# The hook copies renewals into $ETC/tls. Its lineage marker stays, so a
	# reinstall puts the hook back; --purge removes it with $ETC/tls.
	if [ -f "$LE_HOOK" ]; then
		say "removing the Let's Encrypt renewal hook"
		rm -f "$LE_HOOK"
	fi
	if [ $PURGE = 1 ]; then
		db='' key=''
		if [ -f "$cfg" ]; then
			db=$(json_get "$cfg" database)
			key=$(json_get "$cfg" encryption_key_file)
		fi
		say "deleting controller configuration, PSK key, database, generated TLS, and backups"
		rm -rf /var/lib/plaitd /var/backups/plaitd "$ETC/tls"
		[ -z "$db" ] || rm -f "$db" "$db-wal" "$db-shm"
		rm -f "$cfg" "$cfg.plait-old" "$ETC/psk.key" "$NAME_FILE"
		[ -z "$key" ] || rm -f "$key"
		if getent passwd plaitd >/dev/null; then
			say "removing system user plaitd"
			userdel plaitd
		fi
		if getent group plaitd >/dev/null; then groupdel plaitd; fi
	else
		next "kept for a reinstall: $cfg, the PSK key, /var/lib/plaitd (database, generated TLS), /var/backups/plaitd, and the plaitd user; --purge deletes them"
	fi
	[ -z "$port" ] || next "close TCP port $port in the host firewall if nothing else uses it"
}

uninstall() {
	if [ $DO_CONTROLLER = 0 ] && [ $DO_AGENT = 0 ]; then
		if controller_present; then DO_CONTROLLER=1; fi
		if agent_present; then DO_AGENT=1; fi
		if [ $DO_CONTROLLER = 0 ] && [ $DO_AGENT = 0 ]; then
			say "Plait is not installed on this host"
			exit 0
		fi
	fi
	if interactive; then
		what=""
		[ $DO_CONTROLLER = 0 ] || what="$what
  controller: plaitd, plaitctl, the plaitd service"
		[ $DO_AGENT = 0 ] || what="$what
  gateway: plait-agent, its service, plait0, and table inet plait (devices lose access to this site)"
		tell "" "This will remove:$what"
		if [ $PURGE = 1 ]; then
			[ $DO_CONTROLLER = 0 ] || tell "and permanently delete the controller's configuration, PSK key, database," \
				"backups, and the plaitd user. Every device profile and gateway enrollment is lost." \
				"To keep a copy first: runuser -u plaitd -- plaitctl backup FILE (and keep $ETC/psk.key with it)"
			[ $DO_AGENT = 0 ] || tell "and permanently delete the gateway's key and credential (it must be enrolled again)."
			yes_no "Delete everything listed?" n || { tell "Nothing was changed."; exit 0; }
		else
			tell "Configuration, keys, and data are kept, so a later install resumes."
			yes_no "Proceed?" y || { tell "Nothing was changed."; exit 0; }
		fi
	fi
	# The agent first: plait-agent uninstall reads the agent configuration.
	if [ $DO_AGENT = 1 ]; then uninstall_agent; fi
	if [ $DO_CONTROLLER = 1 ]; then uninstall_controller; fi
	systemctl daemon-reload
	if [ ! -e "$PREFIX/plaitd" ] && [ ! -e "$PREFIX/plait-agent" ]; then
		rm -rf "$DOC_DIR"
		rmdir "$ETC" 2>/dev/null || true
	fi
	say "done"
	[ -z "$NEXT" ] || printf 'Next steps:%s\n' "$NEXT"
}

if [ $UNINSTALL = 1 ]; then
	uninstall
	exit 0
fi
if [ $WIZARD = 1 ]; then wizard; fi
if [ $DO_CONTROLLER = 1 ]; then controller; fi
if [ $DO_AGENT = 1 ]; then agent; fi
install_docs

say "done"
[ -z "$NEXT" ] || printf 'Next steps:%s\n' "$NEXT"
