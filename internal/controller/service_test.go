package controller

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"plait/internal/compiler"
	"plait/internal/model"
	"plait/internal/secrets"
	"plait/internal/store"
	"plait/internal/wg"
)

func newService(t *testing.T, pool string) (*Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "plait.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p, err := model.ParsePool(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := secrets.NewSealer(make([]byte, 32))
	svc, err := New(st, p, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st
}

func pubkey(t *testing.T) wg.Key {
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()
	return pub
}

func revisions(t *testing.T, svc *Service, siteID, deviceID string) (int64, int64) {
	t.Helper()
	st, err := svc.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := st.Site(siteID)
	d, _ := st.Device(deviceID)
	return s.DesiredRevision, d.ProfileRevision
}

func TestPragmasOnEveryConnection(t *testing.T) {
	_, st := newService(t, "10.0.0.0/24")
	ctx := context.Background()
	// Hold several connections open at once so the pool must create new ones.
	var conns []interface{ Close() error }
	for i := 0; i < 4; i++ {
		c, err := st.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var fk, busy int
		var mode string
		c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk)
		c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy)
		c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode)
		if fk != 1 || busy != 5000 || mode != "wal" {
			t.Fatalf("conn %d: foreign_keys=%d busy_timeout=%d journal_mode=%s", i, fk, busy, mode)
		}
	}
	for _, c := range conns {
		c.Close()
	}
}

func TestConcurrentEnrollment(t *testing.T) {
	svc, _ := newService(t, "10.0.0.0/26") // 61 allocatable addresses
	ctx := context.Background()
	const n = 40
	var wg sync.WaitGroup
	addrs := make([]netip.Addr, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, addrs[i], errs[i] = svc.EnrollDevice(ctx, fmt.Sprintf("dev-%d", i), pubkey(t), ClientSettings{})
		}(i)
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for i := range addrs {
		if errs[i] != nil {
			t.Fatalf("enroll %d: %v", i, errs[i])
		}
		if seen[addrs[i]] {
			t.Fatalf("duplicate address %s", addrs[i])
		}
		seen[addrs[i]] = true
	}
	// Lowest-free allocation from .2 means the set is exactly .2 .. .41.
	for i := 2; i < 2+n; i++ {
		if !seen[netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})] {
			t.Fatalf("address 10.0.0.%d not allocated", i)
		}
	}
}

func TestPoolExhaustionAndRetention(t *testing.T) {
	svc, _ := newService(t, "10.0.0.0/29") // .2-.6
	ctx := context.Background()
	var first string
	for i := 0; i < 5; i++ {
		id, _, err := svc.EnrollDevice(ctx, fmt.Sprintf("d%d", i), pubkey(t), ClientSettings{})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = id
		}
	}
	if err := svc.RetireDevice(ctx, first); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.EnrollDevice(ctx, "extra", pubkey(t), ClientSettings{})
	if err == nil || !model.IsValidation(err) || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("expected exhaustion (retired reservation retained), got %v", err)
	}
}

func setup(t *testing.T) (*Service, string, string, string) {
	svc, _ := newService(t, "10.0.0.0/24")
	ctx := context.Background()
	home, err := svc.CreateSite(ctx, SiteSpec{
		Name: "Home", EndpointHost: "home.example.net", PublicKey: pubkey(t), EgressInterface: "enp1s0",
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.13.37.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	dev, _, err := svc.EnrollDevice(ctx, "phone", pubkey(t), ClientSettings{})
	if err != nil {
		t.Fatal(err)
	}
	link, err := svc.LinkDevice(ctx, home, dev, model.DefaultKeepalive)
	if err != nil {
		t.Fatal(err)
	}
	return svc, home, dev, link
}

func TestRevisionBumps(t *testing.T) {
	svc, home, dev, link := setup(t)
	ctx := context.Background()
	s0, d0 := revisions(t, svc, home, dev)
	if s0 != 2 || d0 != 2 {
		t.Fatalf("after link: site=%d device=%d, want 2/2", s0, d0)
	}

	// Names alone never reconfigure anything.
	if err := svc.RenameDevice(ctx, dev, "my phone"); err != nil {
		t.Fatal(err)
	}
	if s, d := revisions(t, svc, home, dev); s != s0 || d != d0 {
		t.Fatalf("rename bumped revisions: %d/%d", s, d)
	}

	// Client MTU affects only the device profile.
	if err := svc.SetClientSettings(ctx, dev, ClientSettings{MTU: 1380}); err != nil {
		t.Fatal(err)
	}
	if s, d := revisions(t, svc, home, dev); s != s0 || d != d0+1 {
		t.Fatalf("client MTU: %d/%d", s, d)
	}

	// Keepalive is client-side only.
	if err := svc.SetLinkKeepalive(ctx, link, 0); err != nil {
		t.Fatal(err)
	}
	if s, d := revisions(t, svc, home, dev); s != s0 || d != d0+2 {
		t.Fatalf("keepalive: %d/%d", s, d)
	}

	// PSK rotation affects both.
	if err := svc.RotateLinkPSK(ctx, link); err != nil {
		t.Fatal(err)
	}
	if s, d := revisions(t, svc, home, dev); s != s0+1 || d != d0+3 {
		t.Fatalf("psk rotation: %d/%d", s, d)
	}

	// Disabling the device removes its peer; site bumps.
	if err := svc.SetDeviceEnabled(ctx, dev, false); err != nil {
		t.Fatal(err)
	}
	snap, _ := svc.SiteSnapshot(ctx, home)
	if len(snap.Peers) != 0 || snap.Revision != s0+2 {
		t.Fatalf("disabled device: peers=%d revision=%d", len(snap.Peers), snap.Revision)
	}
	if _, err := svc.ProfileMaterial(ctx, dev); err == nil {
		t.Fatal("profile exported for disabled device")
	}
}

func TestOverlapRejectedAtomically(t *testing.T) {
	svc, home, dev, _ := setup(t)
	ctx := context.Background()
	emerald, err := svc.CreateSite(ctx, SiteSpec{
		Name: "Emerald", EndpointHost: "203.0.113.9", PublicKey: pubkey(t), EgressInterface: "eth0",
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/16")}, // contains Home's LAN
	})
	if err != nil {
		t.Fatal(err) // fine on its own: no device spans both sites yet
	}
	before, _ := svc.State(ctx)
	if _, err := svc.LinkDevice(ctx, emerald, dev, 25); err == nil || !model.IsValidation(err) {
		t.Fatalf("overlapping link accepted: %v", err)
	}
	after, _ := svc.State(ctx)
	if len(after.Links) != len(before.Links) {
		t.Fatal("failed link left a row behind")
	}
	s, d := revisions(t, svc, home, dev)
	if s != 2 || d != 2 {
		t.Fatalf("failed change bumped revisions: %d/%d", s, d)
	}

	// Fix the subnet, then link successfully.
	err = svc.UpdateSite(ctx, emerald, SiteSpec{
		Name: "Emerald", EndpointHost: "203.0.113.9", PublicKey: after.Sites[0].PublicKey, EgressInterface: "eth0",
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.15.0.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LinkDevice(ctx, emerald, dev, 25); err != nil {
		t.Fatal(err)
	}
	m, err := svc.ProfileMaterial(ctx, dev)
	if err != nil || len(m.Peers) != 2 {
		t.Fatalf("profile: %v %+v", err, m)
	}
}

func TestSiteDisableDrains(t *testing.T) {
	svc, home, dev, _ := setup(t)
	ctx := context.Background()
	if err := svc.SetSiteEnabled(ctx, home, false); err != nil {
		t.Fatal(err)
	}
	snap, _ := svc.SiteSnapshot(ctx, home)
	if snap.Peers == nil || len(snap.Peers) != 0 || snap.Revision != 3 {
		t.Fatalf("drained snapshot: %+v", snap)
	}
	m, _ := svc.ProfileMaterial(ctx, dev)
	if len(m.Peers) != 0 || m.Revision != 3 {
		t.Fatalf("device profile after drain: %+v", m)
	}
}

func TestGatewayAccessPorts(t *testing.T) {
	svc, home, dev, _ := setup(t)
	ctx := context.Background()
	s0, d0 := revisions(t, svc, home, dev)
	st, _ := svc.State(ctx)
	sp := siteSpecOf(st, home)
	sp.GatewayTCPPorts = []uint16{2222, 22, 22}
	if err := svc.UpdateSite(ctx, home, sp); err != nil {
		t.Fatal(err)
	}
	s1, d1 := revisions(t, svc, home, dev)
	if s1 != s0+1 || d1 != d0 {
		t.Fatalf("gateway ports must bump the site only: site %d->%d, device %d->%d", s0, s1, d0, d1)
	}
	st, _ = svc.State(ctx)
	snap, err := compiler.SiteSnapshot(st, home)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(snap.Network.GatewayTCPPorts, []uint16{22, 2222}) || snap.Validate() != nil {
		t.Fatalf("snapshot gateway ports = %v", snap.Network.GatewayTCPPorts)
	}
	sp.GatewayTCPPorts = []uint16{0}
	if err := svc.UpdateSite(ctx, home, sp); err == nil || !model.IsValidation(err) {
		t.Fatalf("port 0 accepted: %v", err)
	}
	// Unchanged ports do not bump.
	sp.GatewayTCPPorts = []uint16{22, 2222}
	if err := svc.UpdateSite(ctx, home, sp); err != nil {
		t.Fatal(err)
	}
	if s2, _ := revisions(t, svc, home, dev); s2 != s1 {
		t.Fatalf("unchanged ports bumped the site: %d -> %d", s1, s2)
	}
}

func siteSpecOf(st *model.State, id string) SiteSpec {
	s, _ := st.Site(id)
	return SiteSpec{Name: s.Name, EndpointHost: s.EndpointHost, ListenPort: s.ListenPort, EgressInterface: s.EgressInterface,
		MTU: s.MTU, Subnets: s.Subnets, GatewayTCPPorts: s.GatewayTCPPorts}
}
