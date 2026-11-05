package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"plait/internal/firewall"
	"plait/internal/network"
	"plait/internal/protocol"
	"plait/internal/wg"
)

// WireGuard is the subset of *wgctrl.Client the reconciler uses.
type WireGuard interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// Firewall is the subset of *firewall.Nft the reconciler uses.
type Firewall interface {
	Apply(ctx context.Context, ruleset string) error
	Delete(ctx context.Context) error
	Inspect(ctx context.Context) (*firewall.Observed, error)
	ForeignBlockers(ctx context.Context, t firewall.Traffic) ([]string, error)
}

// Reconciler converges host resources to a desired snapshot. It never uses
// ReplacePeers: unchanged peers, their sessions, and learned endpoints are
// left untouched.
type Reconciler struct {
	WG         WireGuard
	Net        network.Manager
	FW         Firewall
	ReadFile   func(string) ([]byte, error) // sysctl reads; os.ReadFile by default
	PrivateKey wg.Key
	Log        *slog.Logger

	// IncludeFile, when set, is kept identical to the rendered table so a
	// host ruleset that flushes on reload can include it (see Config).
	IncludeFile string
	WriteFile   func(path string, data []byte) error // atomic; writeAtomic by default
}

// includeHeader starts the include file; the rest is the rendered table,
// which replaces any existing plait table whether or not the including
// ruleset flushed first.
const includeHeader = "# Written by plait-agent: Plait's nftables table, for the host ruleset to\n" +
	"# include so reloads keep it. Do not edit; changes are overwritten.\n"

func (r *Reconciler) includeContent(policy firewall.Policy) ([]byte, error) {
	ruleset, err := firewall.Render(policy)
	if err != nil {
		return nil, err
	}
	return []byte(includeHeader + ruleset), nil
}

func (r *Reconciler) readFile(path string) ([]byte, error) {
	if r.ReadFile != nil {
		return r.ReadFile(path)
	}
	return os.ReadFile(path)
}

// syncInclude rewrites the include file when it differs from policy.
func (r *Reconciler) syncInclude(policy firewall.Policy) (bool, error) {
	want, err := r.includeContent(policy)
	if err != nil {
		return false, err
	}
	if have, err := r.readFile(r.IncludeFile); err == nil && bytes.Equal(have, want) {
		return false, nil
	}
	write := r.WriteFile
	if write == nil {
		write = writeAtomic
	}
	return true, write(r.IncludeFile, want)
}

// Result describes one reconciliation pass. Verified is true only when every
// owned resource was observed to match the snapshot afterwards.
type Result struct {
	Revision int64
	Verified bool
	Changes  []string
	Errors   []protocol.ComponentError
	Warnings []string
	Host     map[string]string
}

func (r *Result) fail(component, code string, err error) {
	r.Errors = append(r.Errors, protocol.ComponentError{Component: component, Code: code, Message: firewall.Sanitize(err.Error())})
}

func policyFor(s *protocol.SiteSnapshot) firewall.Policy {
	p := firewall.Policy{
		Interface:       s.Interface.Name,
		Egress:          s.Network.EgressInterface,
		ListenPort:      s.Interface.ListenPort,
		MTU:             s.Interface.MTU,
		LANPrefixes:     s.Network.LANPrefixes,
		GatewayTCPPorts: s.Network.GatewayTCPPorts,
	}
	for _, peer := range s.Peers {
		p.Clients = append(p.Clients, peer.AllowedIPs[0].Addr())
	}
	return p
}

func ipNets(ps []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, len(ps))
	for i, p := range ps {
		out[i] = net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	}
	return out
}

func prefixes(ns []net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ns))
	for _, n := range ns {
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(a.Unmap(), ones))
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return out
}

// peerDiffers reports which fields of an existing peer must change.
func peerDiffers(have wgtypes.Peer, want protocol.SnapshotPeer) (psk, ips, keepalive bool) {
	psk = have.PresharedKey != wgtypes.Key(want.PresharedKey)
	ips = !slices.Equal(prefixes(have.AllowedIPs), want.AllowedIPs)
	keepalive = have.PersistentKeepaliveInterval != 0
	return
}

// Reconcile applies snap. Revocations (peer and route removal) are always
// attempted; new or changed access is enabled only after the firewall and
// return routes for it are in place.
func (r *Reconciler) Reconcile(ctx context.Context, snap *protocol.SiteSnapshot) Result {
	res := Result{Revision: snap.Revision, Host: map[string]string{}}
	name := snap.Interface.Name
	policy := policyFor(snap)
	desired := map[wgtypes.Key]protocol.SnapshotPeer{}
	for _, p := range snap.Peers {
		desired[wgtypes.Key(p.PublicKey)] = p
	}
	enableAccess := true

	r.checkHost(ctx, snap, &res)

	if ok, err := r.Net.LinkExists(snap.Network.EgressInterface); err != nil {
		res.fail("config", "egress-check", err)
		enableAccess = false
	} else if !ok {
		res.fail("config", "egress-missing", fmt.Errorf("egress interface %s does not exist", snap.Network.EgressInterface))
		enableAccess = false
	}

	// Link: without an owned plait0 nothing else can be applied.
	before, _ := r.Net.Link(name)
	if err := r.Net.EnsureLink(name, snap.Interface.MTU); err != nil {
		code := "link-error"
		if errors.Is(err, network.ErrNotOwned) {
			code = "link-not-owned"
		}
		res.fail("link", code, err)
		return res
	}
	if !before.Exists {
		res.Changes = append(res.Changes, "created "+name)
	}

	dev, err := r.WG.Device(name)
	if err != nil {
		res.fail("wireguard", "read-error", err)
		return res
	}

	// Interface identity and revocations first.
	cfg := wgtypes.Config{}
	priv := wgtypes.Key(r.PrivateKey)
	if dev.PrivateKey != priv {
		cfg.PrivateKey = &priv
		res.Changes = append(res.Changes, "set gateway private key")
	}
	if dev.ListenPort != int(snap.Interface.ListenPort) {
		port := int(snap.Interface.ListenPort)
		cfg.ListenPort = &port
		res.Changes = append(res.Changes, fmt.Sprintf("set listen port %d", port))
	}
	existing := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range dev.Peers {
		if _, ok := desired[p.PublicKey]; !ok {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			res.Changes = append(res.Changes, "removed peer "+wg.Key(p.PublicKey).String()[:8])
			continue
		}
		existing[p.PublicKey] = p
	}
	if cfg.PrivateKey != nil || cfg.ListenPort != nil || len(cfg.Peers) > 0 {
		if err := r.WG.ConfigureDevice(name, cfg); err != nil {
			res.fail("wireguard", "configure-error", err)
			enableAccess = false
		}
	}

	// Firewall: replace atomically only when drift is observed.
	if obs, err := r.FW.Inspect(ctx); err != nil {
		res.fail("firewall", "inspect-error", err)
		enableAccess = false
	} else if drift := firewall.Drift(policy, obs); len(drift) > 0 {
		ruleset, err := firewall.Render(policy)
		if err == nil {
			err = r.FW.Apply(ctx, ruleset)
		}
		if err != nil {
			res.fail("firewall", "apply-error", err)
			enableAccess = false
		} else {
			res.Changes = append(res.Changes, "applied firewall ("+strings.Join(drift, "; ")+")")
		}
	}

	if r.IncludeFile != "" {
		if changed, err := r.syncInclude(policy); err != nil {
			res.fail("firewall", "include-write", err)
		} else if changed {
			res.Changes = append(res.Changes, "wrote "+r.IncludeFile)
		}
	}

	// Routes: remove stale owned routes always; add missing ones and fix
	// their source address.
	src := r.icmpSource(snap, &res)
	want := map[netip.Prefix]bool{}
	for _, p := range snap.Peers {
		want[p.AllowedIPs[0]] = true
	}
	owned, err := r.Net.OwnedRoutes(name)
	if err != nil {
		res.fail("routes", "list-error", err)
		enableAccess = false
	} else {
		have := map[netip.Prefix]netip.Addr{}
		for _, rt := range owned {
			have[rt.Dst] = rt.Src
			if !want[rt.Dst] {
				if err := r.Net.DeleteRoute(name, rt.Dst); err != nil {
					res.fail("routes", "delete-error", err)
				} else {
					res.Changes = append(res.Changes, "removed route "+rt.Dst.String())
				}
			}
		}
		for _, p := range sortedPrefixes(want) {
			cur, ok := have[p]
			if ok && cur == src {
				continue
			}
			if err := r.Net.SetRoute(name, network.Route{Dst: p, Src: src}); err != nil {
				res.fail("routes", "add-error", err)
				enableAccess = false
			} else if ok {
				res.Changes = append(res.Changes, fmt.Sprintf("set route %s source %s", p, srcString(src)))
			} else {
				res.Changes = append(res.Changes, "added route "+p.String())
			}
		}
	}

	// New and changed peers, only once their policy and routes exist.
	if enableAccess {
		cfg = wgtypes.Config{}
		for _, want := range snap.Peers {
			key := wgtypes.Key(want.PublicKey)
			psk := wgtypes.Key(want.PresharedKey)
			have, ok := existing[key]
			if !ok {
				cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
					PublicKey: key, PresharedKey: &psk, ReplaceAllowedIPs: true,
					AllowedIPs: ipNets(want.AllowedIPs), PersistentKeepaliveInterval: new(time.Duration),
				})
				res.Changes = append(res.Changes, "added peer for device "+want.DeviceID)
				continue
			}
			pskDiff, ipsDiff, kaDiff := peerDiffers(have, want)
			if !pskDiff && !ipsDiff && !kaDiff {
				continue
			}
			pc := wgtypes.PeerConfig{PublicKey: key, UpdateOnly: true}
			if pskDiff {
				pc.PresharedKey = &psk
			}
			if ipsDiff {
				pc.ReplaceAllowedIPs = true
				pc.AllowedIPs = ipNets(want.AllowedIPs)
			}
			if kaDiff {
				pc.PersistentKeepaliveInterval = new(time.Duration)
			}
			cfg.Peers = append(cfg.Peers, pc)
			res.Changes = append(res.Changes, "updated peer for device "+want.DeviceID)
		}
		if len(cfg.Peers) > 0 {
			if err := r.WG.ConfigureDevice(name, cfg); err != nil {
				res.fail("wireguard", "configure-error", err)
			}
		}
	} else if len(res.Errors) > 0 {
		res.Warnings = append(res.Warnings, "new or changed peer access withheld until earlier failures are resolved")
	}

	for _, e := range r.Verify(ctx, snap) {
		res.fail("verify", "mismatch", errors.New(e))
	}
	res.Verified = len(res.Errors) == 0
	return res
}

func sortedPrefixes(m map[netip.Prefix]bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return out
}

// Verify re-reads every owned resource and reports mismatches without
// changing anything.
func (r *Reconciler) Verify(ctx context.Context, snap *protocol.SiteSnapshot) []string {
	var out []string
	policy := policyFor(snap)
	name := snap.Interface.Name
	link, err := r.Net.Link(name)
	switch {
	case err != nil:
		out = append(out, "link: "+err.Error())
	case !link.Exists || !link.Owned:
		out = append(out, name+" missing or not owned")
	case !link.Up:
		out = append(out, name+" is down")
	case link.MTU != snap.Interface.MTU:
		out = append(out, fmt.Sprintf("%s MTU %d, want %d", name, link.MTU, snap.Interface.MTU))
	}

	dev, err := r.WG.Device(name)
	if err != nil {
		out = append(out, "wireguard: "+err.Error())
	} else {
		if dev.PrivateKey != wgtypes.Key(r.PrivateKey) {
			out = append(out, "gateway private key mismatch")
		}
		if dev.ListenPort != int(snap.Interface.ListenPort) {
			out = append(out, fmt.Sprintf("listen port %d, want %d", dev.ListenPort, snap.Interface.ListenPort))
		}
		want := map[wgtypes.Key]protocol.SnapshotPeer{}
		for _, p := range snap.Peers {
			want[wgtypes.Key(p.PublicKey)] = p
		}
		for _, p := range dev.Peers {
			w, ok := want[p.PublicKey]
			if !ok {
				out = append(out, "unexpected peer "+wg.Key(p.PublicKey).String()[:8])
				continue
			}
			if psk, ips, ka := peerDiffers(p, w); psk || ips || ka {
				out = append(out, "peer for device "+w.DeviceID+" differs")
			}
			delete(want, p.PublicKey)
		}
		for _, w := range want {
			out = append(out, "missing peer for device "+w.DeviceID)
		}
	}

	if obs, err := r.FW.Inspect(ctx); err != nil {
		out = append(out, "firewall: "+err.Error())
	} else {
		out = append(out, firewall.Drift(policy, obs)...)
	}
	if r.IncludeFile != "" {
		want, err := r.includeContent(policy)
		if have, rerr := r.readFile(r.IncludeFile); err != nil || rerr != nil || !bytes.Equal(have, want) {
			out = append(out, "nft include file "+r.IncludeFile+" is missing or out of date")
		}
	}

	owned, err := r.Net.OwnedRoutes(name)
	if err != nil {
		out = append(out, "routes: "+err.Error())
	} else {
		byDst := func(a, b network.Route) int { return a.Dst.Addr().Compare(b.Dst.Addr()) }
		got := slices.Clone(owned)
		slices.SortFunc(got, byDst)
		src := r.icmpSource(snap, &Result{})
		var want []network.Route
		for _, p := range snap.Peers {
			want = append(want, network.Route{Dst: p.AllowedIPs[0], Src: src})
		}
		slices.SortFunc(want, byDst)
		if !slices.Equal(got, want) {
			out = append(out, "owned routes differ from desired peers")
		}
	}
	return out
}

// icmpSource picks the preferred source address for return routes: the
// gateway's lowest address on the egress interface inside an advertised
// prefix, which every client's AllowedIPs for this site accepts. Without
// one, gateway-generated ICMP errors would be dropped by clients, so it is
// reported; access itself still works.
func (r *Reconciler) icmpSource(snap *protocol.SiteSnapshot, res *Result) netip.Addr {
	addrs, err := r.Net.Addrs(snap.Network.EgressInterface)
	if err != nil {
		return netip.Addr{} // a missing egress interface is reported elsewhere
	}
	var best netip.Addr
	for _, a := range addrs {
		ip := a.Addr()
		if !ip.Is4() || (best.IsValid() && best.Less(ip)) {
			continue
		}
		for _, lan := range snap.Network.LANPrefixes {
			if lan.Contains(ip) {
				best = ip
				break
			}
		}
	}
	if !best.IsValid() && len(snap.Peers) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("no address on %s lies in an advertised subnet; "+
			"ICMP errors from the gateway (path MTU discovery, traceroute) will not reach clients", snap.Network.EgressInterface))
	}
	return best
}

func srcString(a netip.Addr) string {
	if !a.IsValid() {
		return "unset"
	}
	return a.String()
}

// checkHost inspects host prerequisites without changing host-wide policy.
func (r *Reconciler) checkHost(ctx context.Context, snap *protocol.SiteSnapshot, res *Result) {
	sysctl := func(path string) (string, bool) {
		b, err := r.readFile(path)
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(b)), true
	}

	fwd, ok := sysctl("/proc/sys/net/ipv4/ip_forward")
	res.Host["ip_forward"] = fwd
	if !ok || fwd != "1" {
		res.fail("host", "ip-forward-disabled", errors.New("net.ipv4.ip_forward is not enabled; enable it during host setup"))
	}

	// Effective rp_filter is max(all, interface).
	all, _ := sysctl("/proc/sys/net/ipv4/conf/all/rp_filter")
	for _, ifname := range []string{snap.Interface.Name, snap.Network.EgressInterface} {
		v, ok := sysctl("/proc/sys/net/ipv4/conf/" + ifname + "/rp_filter")
		if !ok {
			continue
		}
		eff := max(all, v) // single digits 0-2 compare correctly as strings
		res.Host["rp_filter."+ifname] = eff
	}

	t := firewall.Traffic{Interface: snap.Interface.Name, Egress: snap.Network.EgressInterface, ListenPort: snap.Interface.ListenPort}
	if blockers, err := r.FW.ForeignBlockers(ctx, t); err == nil {
		res.Warnings = append(res.Warnings, blockers...)
	}

	conflicts, err := r.Net.ConflictingRoutes(snap.Interface.Name, snap.Network.ClientPool)
	if err != nil {
		return
	}
	clients := map[string]bool{}
	for _, p := range snap.Peers {
		clients[p.AllowedIPs[0].String()] = true
	}
	for _, c := range conflicts {
		dst, _, _ := strings.Cut(c, " ")
		if clients[dst] {
			res.fail("routes", "conflict", fmt.Errorf("foreign route conflicts with a client return route: %s", c))
		} else {
			res.Warnings = append(res.Warnings, "route into the client pool not owned by Plait: "+c)
		}
	}
}

// Telemetry reports per-peer activity keyed by device ID.
func (r *Reconciler) Telemetry(snap *protocol.SiteSnapshot) []protocol.PeerTelemetry {
	dev, err := r.WG.Device(snap.Interface.Name)
	if err != nil {
		return nil
	}
	ids := map[wgtypes.Key]string{}
	for _, p := range snap.Peers {
		ids[wgtypes.Key(p.PublicKey)] = p.DeviceID
	}
	var out []protocol.PeerTelemetry
	for _, p := range dev.Peers {
		id, ok := ids[p.PublicKey]
		if !ok {
			continue
		}
		out = append(out, protocol.PeerTelemetry{
			DeviceID: id, LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes,
		})
	}
	return out
}

// Teardown deliberately removes everything Plait owns on this host: the
// firewall table, its include file, and plait0 (its routes go with it).
func (r *Reconciler) Teardown(ctx context.Context, name string) error {
	var rm error
	if r.IncludeFile != "" {
		if err := os.Remove(r.IncludeFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			rm = err
		}
	}
	return errors.Join(rm, r.FW.Delete(ctx), r.Net.DeleteLink(name))
}
