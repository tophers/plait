package compiler

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"plait/internal/model"
	"plait/internal/wg"
)

func key(t *testing.T) wg.Key {
	t.Helper()
	k, err := wg.GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixture(t *testing.T) *model.State {
	pool, _ := model.ParsePool("10.0.0.0/24", nil)
	return &model.State{
		Pool: pool,
		Sites: []model.Site{
			{ID: "s-home", Name: "Home", EndpointHost: "home.example.net", ListenPort: 51111, PublicKey: key(t),
				EgressInterface: "enp1s0", MTU: 1420, Enabled: true, DesiredRevision: 3,
				Subnets: []netip.Prefix{netip.MustParsePrefix("10.13.37.0/24")}},
			{ID: "s-emerald", Name: "Emerald", EndpointHost: "2001:db8::1", ListenPort: 51111, PublicKey: key(t),
				EgressInterface: "eth0", MTU: 1420, Enabled: true, DesiredRevision: 7,
				Subnets: []netip.Prefix{netip.MustParsePrefix("10.15.0.0/24")}},
		},
		Devices: []model.Device{
			{ID: "d-phone", Name: "phone", PublicKey: key(t), AssignedIPv4: netip.MustParseAddr("10.0.0.4"),
				Enabled: true, ProfileRevision: 2, DNSServers: []netip.Addr{netip.MustParseAddr("10.13.37.37")}},
			{ID: "d-laptop", Name: "laptop", PublicKey: key(t), AssignedIPv4: netip.MustParseAddr("10.0.0.2"),
				Enabled: true, ProfileRevision: 1},
		},
		Links: []model.Link{
			{ID: "l1", SiteID: "s-home", DeviceID: "d-phone", PresharedKey: key(t), PersistentKeepalive: 25, Enabled: true},
			{ID: "l2", SiteID: "s-emerald", DeviceID: "d-phone", PresharedKey: key(t), PersistentKeepalive: 25, Enabled: true},
			{ID: "l3", SiteID: "s-home", DeviceID: "d-laptop", PresharedKey: key(t), PersistentKeepalive: 0, Enabled: true},
		},
	}
}

func TestProfileMaterial(t *testing.T) {
	st := fixture(t)
	if err := Validate(st); err != nil {
		t.Fatal(err)
	}
	m, err := ProfileMaterial(st, "d-phone")
	if err != nil {
		t.Fatal(err)
	}
	if m.Address.String() != "10.0.0.4/32" || len(m.Peers) != 2 {
		t.Fatalf("unexpected material: %+v", m)
	}
	// Ordered by site ID, independent of names.
	if m.Peers[0].SiteID != "s-emerald" || m.Peers[0].Endpoint != "[2001:db8::1]:51111" {
		t.Fatalf("unexpected first peer: %+v", m.Peers[0])
	}
	if m.Peers[1].Endpoint != "home.example.net:51111" {
		t.Fatalf("unexpected endpoint: %s", m.Peers[1].Endpoint)
	}
	for _, p := range m.Peers {
		for _, a := range p.AllowedIPs {
			if a.Overlaps(st.Pool.Prefix) {
				t.Fatalf("client pool advertised through %s", p.SiteName)
			}
		}
	}
	if len(m.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", m.Warnings)
	}
}

func TestDeterministic(t *testing.T) {
	st := fixture(t)
	a, _ := ProfileMaterial(st, "d-phone")
	// Reverse input order; output must not change.
	st.Links[0], st.Links[1] = st.Links[1], st.Links[0]
	st.Sites[0], st.Sites[1] = st.Sites[1], st.Sites[0]
	b, _ := ProfileMaterial(st, "d-phone")
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("profile not deterministic:\n%s\n%s", ja, jb)
	}

	sa, _ := SiteSnapshot(st, "s-home")
	st.Devices[0], st.Devices[1] = st.Devices[1], st.Devices[0]
	sb, _ := SiteSnapshot(st, "s-home")
	ja, _ = json.Marshal(sa)
	jb, _ = json.Marshal(sb)
	if string(ja) != string(jb) {
		t.Fatalf("snapshot not deterministic")
	}
	if sa.Peers[0].AllowedIPs[0].String() != "10.0.0.2/32" {
		t.Fatalf("snapshot peers not ordered by address: %+v", sa.Peers)
	}
}

func TestOverlappingSitesRejected(t *testing.T) {
	st := fixture(t)
	st.Sites[1].Subnets = []netip.Prefix{netip.MustParsePrefix("10.13.0.0/16")} // contains Home's /24
	_, err := ProfileMaterial(st, "d-phone")
	if err == nil || !model.IsValidation(err) {
		t.Fatalf("nested overlap accepted: %v", err)
	}
	if err := Validate(st); err == nil {
		t.Fatal("Validate accepted overlapping profile")
	}
	// Overlap is fine when no single device spans both sites.
	st.Links[1].Enabled = false
	if err := Validate(st); err != nil {
		t.Fatalf("overlap without shared device rejected: %v", err)
	}
}

func TestDisabledSiteHasEmptyPeers(t *testing.T) {
	st := fixture(t)
	st.Sites[0].Enabled = false
	snap, err := SiteSnapshot(st, "s-home")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Peers == nil || len(snap.Peers) != 0 {
		t.Fatalf("disabled site peers = %#v, want explicit empty", snap.Peers)
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(snap)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	if _, ok := raw["peers"].([]any); !ok {
		t.Fatalf("peers not serialized as array: %s", b)
	}
}

func TestInactiveDeviceExportRejected(t *testing.T) {
	st := fixture(t)
	st.Devices[0].Retired = true
	if _, err := ProfileMaterial(st, "d-phone"); !errors.Is(err, ErrDeviceInactive) {
		t.Fatalf("err = %v", err)
	}
	snap, _ := SiteSnapshot(st, "s-home")
	for _, p := range snap.Peers {
		if p.DeviceID == "d-phone" {
			t.Fatal("retired device still in site peer set")
		}
	}
}

func TestDNSWarning(t *testing.T) {
	st := fixture(t)
	st.Links[0].Enabled = false // phone loses Home, which hosts its resolver
	m, err := ProfileMaterial(st, "d-phone")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Warnings) != 1 {
		t.Fatalf("warnings = %v", m.Warnings)
	}
}
