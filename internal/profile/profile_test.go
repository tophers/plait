package profile

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"plait/internal/protocol"
	"plait/internal/wg"
)

func material(t *testing.T) (*protocol.ProfileMaterial, wg.Key) {
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()
	site, _ := wg.GeneratePrivateKey()
	psk, _ := wg.GeneratePresharedKey()
	return &protocol.ProfileMaterial{
		SchemaVersion: protocol.ProfileSchemaVersion,
		DeviceID:      "d", DeviceName: "phone", Revision: 4, PublicKey: pub,
		Address:      netip.MustParsePrefix("10.0.0.4/32"),
		DNSServers:   []netip.Addr{netip.MustParseAddr("10.13.37.37")},
		SearchDomains: []string{"home.lan", "cabin.lan"},
		Peers: []protocol.ProfilePeer{{
			SiteID: "s", SiteName: "Home", PublicKey: site, Endpoint: "home.example.net:51111",
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.13.37.0/24"), netip.MustParsePrefix("10.14.0.0/24")},
			PresharedKey: psk, PersistentKeepalive: 0,
		}},
	}, priv
}

func TestRender(t *testing.T) {
	m, priv := material(t)
	full, err := Render(m, priv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PrivateKey = " + priv.String(),
		"Address = 10.0.0.4/32",
		"DNS = 10.13.37.37, home.lan, cabin.lan",
		"AllowedIPs = 10.13.37.0/24, 10.14.0.0/24",
		"# Site: Home",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("full profile missing %q:\n%s", want, full)
		}
	}
	if strings.Contains(full, "MTU") {
		t.Error("MTU emitted without override")
	}

	min, err := Render(m, priv, Options{Minify: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(min, "#") || strings.Contains(min, " ") || strings.Contains(min, "\n\n") {
		t.Errorf("minified profile has comments or whitespace:\n%s", min)
	}
	if strings.Contains(min, "PersistentKeepalive") {
		t.Error("disabled keepalive emitted in minified profile")
	}
	if !strings.Contains(min, "AllowedIPs=10.13.37.0/24,10.14.0.0/24\n") {
		t.Errorf("minified AllowedIPs wrong:\n%s", min)
	}

	m.MTU = 1380
	withMTU, _ := Render(m, priv, Options{Minify: true})
	if !strings.Contains(withMTU, "MTU=1380\n") {
		t.Error("MTU override missing")
	}
}

func TestRenderKeyMismatch(t *testing.T) {
	m, _ := material(t)
	other, _ := wg.GeneratePrivateKey()
	if _, err := Render(m, other, Options{}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderRefusesControlCharacters(t *testing.T) {
	for name, mutate := range map[string]func(*protocol.ProfileMaterial){
		"dns zone":    func(m *protocol.ProfileMaterial) { m.DNSServers[0] = netip.MustParseAddr("fe80::1%eth0\nPreUp = id") },
		"endpoint":    func(m *protocol.ProfileMaterial) { m.Peers[0].Endpoint = "[fe80::1%x\nPostUp = id]:51111" },
		"search":      func(m *protocol.ProfileMaterial) { m.SearchDomains = []string{"lan\rPostUp = id"} },
		"device name": func(m *protocol.ProfileMaterial) { m.DeviceName = "phone\nPreUp = id" },
		"site name":   func(m *protocol.ProfileMaterial) { m.Peers[0].SiteName = "Home PreUp = id" },
	} {
		for _, minify := range []bool{false, true} {
			m, priv := material(t)
			mutate(m)
			if minify && strings.HasSuffix(name, " name") {
				continue // names appear only in comments, which minify omits
			}
			if out, err := Render(m, priv, Options{Minify: minify}); !errors.Is(err, ErrUnsafeValue) {
				t.Errorf("%s (minify %v): err = %v, output:\n%s", name, minify, err, out)
			}
		}
	}
}
