package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"plait/internal/firewall"
	"plait/internal/network"
	"plait/internal/protocol"
	"plait/internal/wg"
)

type peerKeys struct {
	priv, pub, psk wg.Key
}

func newPeer(t *testing.T) peerKeys {
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()
	psk, _ := wg.GeneratePresharedKey()
	return peerKeys{priv, pub, psk}
}

func snapshot(gw wg.Key, rev int64, peers map[string]peerKeys) *protocol.SiteSnapshot {
	pub, _ := gw.PublicKey()
	s := &protocol.SiteSnapshot{
		SchemaVersion: protocol.SnapshotSchemaVersion,
		SiteID:        "site-1",
		Revision:      rev,
		Interface:     protocol.SiteInterface{Name: "plait0", PublicKey: pub, ListenPort: 51111, MTU: 1420},
		Network: protocol.SiteNetwork{
			ClientPool:      netip.MustParsePrefix("10.0.0.0/24"),
			EgressInterface: "enp1s0",
			LANPrefixes:     []netip.Prefix{netip.MustParsePrefix("10.15.0.0/24")},
			Masquerade:      true,
		},
		Peers: []protocol.SnapshotPeer{},
	}
	for addr, k := range peers {
		s.Peers = append(s.Peers, protocol.SnapshotPeer{
			DeviceID: "dev-" + addr, PublicKey: k.pub, PresharedKey: k.psk,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(addr + "/32")},
		})
	}
	slices.SortFunc(s.Peers, func(a, b protocol.SnapshotPeer) int { return a.AllowedIPs[0].Addr().Compare(b.AllowedIPs[0].Addr()) })
	return s
}

func newRecon(t *testing.T) (*Reconciler, *fakeHost, wg.Key) {
	h := newFakeHost()
	gw, _ := wg.GeneratePrivateKey()
	r := &Reconciler{WG: h, Net: h, FW: h, ReadFile: h.readFile, PrivateKey: gw, Log: slog.New(slog.DiscardHandler)}
	return r, h, gw
}

func indexOf(ops []string, prefix string) int {
	return slices.IndexFunc(ops, func(s string) bool { return strings.HasPrefix(s, prefix) })
}

func TestFreshApplyOrdering(t *testing.T) {
	r, h, gw := newRecon(t)
	a := newPeer(t)
	res := r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": a}))
	if !res.Verified {
		t.Fatalf("not verified: %+v", res.Errors)
	}
	fw, route, peer := indexOf(h.ops, "firewall apply"), indexOf(h.ops, "route add"), indexOf(h.ops, "peer add")
	if fw < 0 || route < 0 || peer < 0 || !(fw < peer && route < peer) {
		t.Fatalf("access enabled before policy and routes: %v", h.ops)
	}
	if !h.hasRoute("10.0.0.4/32") {
		t.Fatal("return route missing")
	}
	if h.dev.PrivateKey != wgtypes.Key(gw) || h.dev.ListenPort != 51111 {
		t.Fatal("interface identity not configured")
	}
	if res.Host["rp_filter.plait0"] != "2" {
		t.Fatalf("effective rp_filter = %q, want max(all=1, plait0=2) = 2", res.Host["rp_filter.plait0"])
	}
}

func TestUnchangedReconcileIsNoop(t *testing.T) {
	r, h, gw := newRecon(t)
	snap := snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	r.Reconcile(context.Background(), snap)
	h.ops = nil
	res := r.Reconcile(context.Background(), snap)
	if !res.Verified || len(h.ops) != 0 || len(res.Changes) != 0 {
		t.Fatalf("second pass changed state: ops=%v changes=%v", h.ops, res.Changes)
	}
}

func TestAddPeerPreservesExistingSession(t *testing.T) {
	r, h, gw := newRecon(t)
	a, b := newPeer(t), newPeer(t)
	r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": a}))
	h.setEndpoint(wgtypes.Key(a.pub), "198.51.100.7:40000")
	h.ops = nil

	res := r.Reconcile(context.Background(), snapshot(gw, 2, map[string]peerKeys{"10.0.0.4": a, "10.0.0.5": b}))
	if !res.Verified {
		t.Fatalf("not verified: %+v", res.Errors)
	}
	for _, op := range h.ops {
		if strings.Contains(op, a.pub.String()[:8]) {
			t.Fatalf("unchanged peer touched: %s", op)
		}
	}
	dev, _ := h.Device("plait0")
	for _, p := range dev.Peers {
		if p.PublicKey == wgtypes.Key(a.pub) && (p.Endpoint == nil || p.Endpoint.String() != "198.51.100.7:40000") {
			t.Fatalf("learned endpoint lost: %v", p.Endpoint)
		}
	}
}

func TestRevocationProceedsWhenFirewallFails(t *testing.T) {
	r, h, gw := newRecon(t)
	a, b := newPeer(t), newPeer(t)
	r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": a}))
	h.applyErr = errors.New("nft exploded")
	h.ops = nil

	// Revision 2 revokes a and grants b; the firewall cannot be updated.
	res := r.Reconcile(context.Background(), snapshot(gw, 2, map[string]peerKeys{"10.0.0.5": b}))
	if res.Verified {
		t.Fatal("verified despite firewall failure")
	}
	if indexOf(h.ops, "peer remove "+wgtypes.Key(a.pub).String()[:8]) < 0 {
		t.Fatalf("revocation not applied: %v", h.ops)
	}
	if indexOf(h.ops, "peer add") >= 0 {
		t.Fatalf("new access enabled without firewall policy: %v", h.ops)
	}
	if h.hasRoute("10.0.0.4/32") {
		t.Fatal("revoked route retained")
	}

	// Once the firewall recovers, the same desired state converges.
	h.applyErr = nil
	if res := r.Reconcile(context.Background(), snapshot(gw, 2, map[string]peerKeys{"10.0.0.5": b})); !res.Verified {
		t.Fatalf("did not converge: %+v", res.Errors)
	}
}

func TestRefusesForeignInterface(t *testing.T) {
	r, h, gw := newRecon(t)
	h.links["plait0"] = &network.LinkState{Exists: true, Owned: false}
	res := r.Reconcile(context.Background(), snapshot(gw, 1, nil))
	if res.Verified || len(res.Errors) == 0 || res.Errors[0].Code != "link-not-owned" {
		t.Fatalf("errors = %+v", res.Errors)
	}
	if len(h.ops) != 0 {
		t.Fatalf("touched host state: %v", h.ops)
	}
}

func TestDriftRepair(t *testing.T) {
	r, h, gw := newRecon(t)
	snap := snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	r.Reconcile(context.Background(), snap)

	delete(h.routes, netip.MustParsePrefix("10.0.0.4/32"))
	h.routes[netip.MustParsePrefix("10.0.0.99/32")] = netip.Addr{} // stale owned route
	h.observed = nil                                       // table deleted externally
	h.links["plait0"].Up = false

	res := r.Reconcile(context.Background(), snap)
	if !res.Verified {
		t.Fatalf("drift not repaired: %+v", res.Errors)
	}
	if !h.hasRoute("10.0.0.4/32") || h.hasRoute("10.0.0.99/32") {
		t.Fatalf("routes not repaired: %v", h.routes)
	}
}

func TestPSKRotationUpdatesInPlace(t *testing.T) {
	r, h, gw := newRecon(t)
	a := newPeer(t)
	r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": a}))
	h.ops = nil
	a.psk, _ = wg.GeneratePresharedKey()
	res := r.Reconcile(context.Background(), snapshot(gw, 2, map[string]peerKeys{"10.0.0.4": a}))
	if !res.Verified {
		t.Fatalf("%+v", res.Errors)
	}
	if len(h.ops) != 1 || !strings.HasPrefix(h.ops[0], "peer update") {
		t.Fatalf("ops = %v, want a single in-place update", h.ops)
	}
}

func TestIPForwardDisabledIsReported(t *testing.T) {
	r, h, gw := newRecon(t)
	h.sysctl["/proc/sys/net/ipv4/ip_forward"] = "0"
	res := r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t)}))
	if res.Verified {
		t.Fatal("verified with forwarding disabled")
	}
	if len(h.dev.Peers) != 1 {
		t.Fatal("configuration not applied")
	}
}

func TestEmptySnapshotRemovesAllPeers(t *testing.T) {
	r, h, gw := newRecon(t)
	r.Reconcile(context.Background(), snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t), "10.0.0.5": newPeer(t)}))
	res := r.Reconcile(context.Background(), snapshot(gw, 2, nil))
	if !res.Verified || len(h.dev.Peers) != 0 || len(h.routes) != 0 {
		t.Fatalf("drain incomplete: peers=%d routes=%d errors=%+v", len(h.dev.Peers), len(h.routes), res.Errors)
	}
}

func TestNftIncludeFileFollowsTable(t *testing.T) {
	r, h, gw := newRecon(t)
	path := filepath.Join(t.TempDir(), "plait.nft")
	r.IncludeFile = path
	r.ReadFile = func(p string) ([]byte, error) {
		if b, err := h.readFile(p); err == nil {
			return b, nil
		}
		return os.ReadFile(p)
	}
	ctx := context.Background()
	snap := snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t)})

	res := r.Reconcile(ctx, snap)
	if !res.Verified || !slices.Contains(res.Changes, "wrote "+path) {
		t.Fatalf("include not written: verified=%v changes=%v errors=%v", res.Verified, res.Changes, res.Errors)
	}
	b, _ := os.ReadFile(path)
	ruleset, _ := firewall.Render(policyFor(snap))
	if !strings.HasPrefix(string(b), "# Written by plait-agent") || !strings.HasSuffix(string(b), ruleset) {
		t.Fatalf("include content:\n%s", b)
	}
	// It must replace an existing table even where the host did not flush.
	if !strings.Contains(string(b), "table inet plait {}\ndelete table inet plait\n") {
		t.Fatal("include does not replace an existing plait table")
	}

	if res := r.Reconcile(ctx, snap); len(res.Changes) != 0 {
		t.Fatalf("unchanged include rewritten: %v", res.Changes)
	}

	os.WriteFile(path, []byte("# edited\n"), 0o600)
	if d := r.Verify(ctx, snap); !slices.ContainsFunc(d, func(s string) bool { return strings.Contains(s, "include file") }) {
		t.Fatalf("edited include not reported: %v", d)
	}
	if res := r.Reconcile(ctx, snap); !res.Verified || !slices.Contains(res.Changes, "wrote "+path) {
		t.Fatalf("edited include not restored: %+v", res)
	}

	r.WriteFile = func(string, []byte) error { return errors.New("read-only file system") }
	os.Remove(path)
	if res := r.Reconcile(ctx, snap); res.Verified || !slices.ContainsFunc(res.Errors, func(e protocol.ComponentError) bool { return e.Code == "include-write" }) {
		t.Fatalf("write failure not reported: %+v", res.Errors)
	}
	r.WriteFile = nil

	r.Reconcile(ctx, snap)
	if err := r.Teardown(ctx, snap.Interface.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uninstall left the include file")
	}
}

func TestCheckNftIncludeFile(t *testing.T) {
	for _, ok := range []string{"", "/etc/nftables/conf.d/plait.nft"} {
		if err := CheckNftIncludeFile(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"plait.nft", "/etc/nftables/conf.d/plait.conf", "/etc/nftables/../plait.nft", "/etc/nftables/conf.d/"} {
		if err := CheckNftIncludeFile(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReturnRoutesCarryICMPSource(t *testing.T) {
	r, h, gw := newRecon(t)
	ctx := context.Background()
	// The egress interface also carries a management address outside the
	// advertised prefixes; only the LAN address is acceptable to clients.
	h.addrs["enp1s0"] = []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24"), netip.MustParsePrefix("10.15.0.9/24"), netip.MustParsePrefix("10.15.0.1/24")}
	snap := snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	res := r.Reconcile(ctx, snap)
	if !res.Verified || len(res.Warnings) != 0 {
		t.Fatalf("errors %+v warnings %v", res.Errors, res.Warnings)
	}
	if src := h.routes[netip.MustParsePrefix("10.0.0.4/32")]; src != netip.MustParseAddr("10.15.0.1") {
		t.Fatalf("route source = %v, want 10.15.0.1", src)
	}

	// The address moves: drift is reported and the route is replaced in place.
	h.addrs["enp1s0"] = []netip.Prefix{netip.MustParsePrefix("10.15.0.2/24")}
	if d := r.Verify(ctx, snap); !slices.Contains(d, "owned routes differ from desired peers") {
		t.Fatalf("stale route source not reported: %v", d)
	}
	h.ops = nil
	r.Reconcile(ctx, snap)
	if src := h.routes[netip.MustParsePrefix("10.0.0.4/32")]; src != netip.MustParseAddr("10.15.0.2") || indexOf(h.ops, "route del") >= 0 {
		t.Fatalf("route source = %v, ops %v", src, h.ops)
	}

	// No address in an advertised prefix: access still works, with a warning.
	h.addrs["enp1s0"] = []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}
	res = r.Reconcile(ctx, snap)
	if !res.Verified || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "ICMP errors") {
		t.Fatalf("errors %+v warnings %v", res.Errors, res.Warnings)
	}
	if src := h.routes[netip.MustParsePrefix("10.0.0.4/32")]; src.IsValid() {
		t.Fatalf("route source = %v, want unset", src)
	}
}
