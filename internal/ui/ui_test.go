package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"plait/internal/api"
	"plait/internal/controller"
	"plait/internal/model"
	"plait/internal/protocol"
	"plait/internal/secrets"
	"plait/internal/store"
	"plait/internal/wg"
)

func TestMain(m *testing.M) {
	controller.Argon2Params.Memory = 1024
	controller.Argon2Params.Time = 1
	os.Exit(m.Run())
}

const password = "ui test password"

type env struct {
	ui     *UI
	t      *testing.T
	svc    *controller.Service
	srv    *httptest.Server
	client *http.Client
	csrf   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "plaitd.db"))
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := model.ParsePool("10.0.0.0/24", nil)
	sealer, _ := secrets.NewSealer(bytes.Repeat([]byte{3}, 32))
	svc, err := controller.New(st, pool, sealer)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	a := api.New(svc, log)
	u, err := New(svc, log, a.Limiter())
	if err != nil {
		t.Fatal(err)
	}
	a.UI = u.Handler()
	srv := httptest.NewTLSServer(a.Handler())
	t.Cleanup(func() { srv.Close(); st.Close() })
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := svc.CreateAdmin(ctx, "admin", password); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, svc: svc, srv: srv, client: client, ui: u}
}

func (e *env) get(path string) (*http.Response, string) {
	e.t.Helper()
	resp, err := e.client.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) post(path string, form url.Values, headers ...string) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var csrfMeta = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

func (e *env) login() {
	e.t.Helper()
	resp, _ := e.post("/login", url.Values{"username": {"admin"}, "password": {password}, "next": {"/"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("login: %d", resp.StatusCode)
	}
	_, body := e.get("/")
	m := csrfMeta.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatal("no CSRF token on dashboard")
	}
	e.csrf = m[1]
}

// form posts with the CSRF token and expects a redirect.
func (e *env) form(path string, v url.Values) *http.Response {
	e.t.Helper()
	if v == nil {
		v = url.Values{}
	}
	v.Set("csrf_token", e.csrf)
	resp, body := e.post(path, v)
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("POST %s: %d %s", path, resp.StatusCode, body)
	}
	return resp
}

func pub(t *testing.T) wg.Key {
	k, _ := wg.GeneratePrivateKey()
	p, _ := k.PublicKey()
	return p
}

// fixture builds an enrolled site, a pending site, and a linked device whose
// resolver lives in the enrolled site.
func (e *env) fixture() (home, pending, dev string) {
	ctx := controller.WithActor(context.Background(), "test")
	var err error
	home, err = e.svc.CreateSite(ctx, controller.SiteSpec{Name: "Home", EndpointHost: "home.example.net", PublicKey: pub(e.t),
		EgressInterface: "eth0", Subnets: []netip.Prefix{netip.MustParsePrefix("10.13.37.0/24")}})
	if err != nil {
		e.t.Fatal(err)
	}
	pending, err = e.svc.CreateSite(ctx, controller.SiteSpec{Name: "Lake", EndpointHost: "lake.example.net",
		EgressInterface: "eth0", Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}})
	if err != nil {
		e.t.Fatal(err)
	}
	dev, _, err = e.svc.EnrollDevice(ctx, "phone", pub(e.t), controller.ClientSettings{})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.LinkDevice(ctx, home, dev, 25); err != nil {
		e.t.Fatal(err)
	}
	if err := e.svc.SetClientSettings(ctx, dev, controller.ClientSettings{DNSServers: []netip.Addr{netip.MustParseAddr("10.13.37.53")}}); err != nil {
		e.t.Fatal(err)
	}
	return home, pending, dev
}

func TestLoginFlowAndHeaders(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.get("/devices")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?next=%2Fdevices" {
		t.Fatalf("unauthenticated: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := e.get("/login")
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(body, `name="password"`) {
		t.Fatal("login page headers or form missing")
	}
	resp, body = e.post("/login", url.Values{"username": {"admin"}, "password": {"wrong password"}})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Invalid username, password, or authentication code") {
		t.Fatalf("bad login: %d", resp.StatusCode)
	}
	// Bodies past maxFormBytes are not parsed; the login fails as empty.
	resp, _ = e.post("/login", url.Values{"username": {"admin"}, "password": {strings.Repeat("x", maxFormBytes)}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oversized login body: %d, want 401", resp.StatusCode)
	}
	// Open redirects are refused.
	resp, _ = e.post("/login", url.Values{"username": {"admin"}, "password": {password}, "next": {"//evil.example/x"}})
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("next=//evil redirected to %q", resp.Header.Get("Location"))
	}
	for in, want := range map[string]string{"/sites/x": "/sites/x", "https://evil": "/", "/\\evil": "/", "": "/"} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q", in, got)
		}
	}
}

func TestFormsRequireCSRFAndSameOrigin(t *testing.T) {
	e := newEnv(t)
	e.login()
	v := url.Values{"name": {"Home"}, "endpoint_host": {"h.example"}, "egress_interface": {"eth0"}, "subnets": {"10.13.37.0/24"}}
	if resp, _ := e.post("/sites", v); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	v.Set("csrf_token", e.csrf)
	if resp, _ := e.post("/sites", v, "Origin", "https://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", resp.StatusCode)
	}
	// Headers real browsers send. Same-origin form posts may carry
	// "Origin: null" (e.g. under a no-referrer policy); Sec-Fetch-Site decides.
	for _, h := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site", "Origin", e.srv.URL},
		{"Origin", "null"},
	} {
		if resp, _ := e.post("/sites", v, h...); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%v: %d, want 403", h, resp.StatusCode)
		}
	}
	browser := url.Values{"name": {"Cabin"}, "endpoint_host": {"c.example"}, "egress_interface": {"eth0"}, "subnets": {"10.13.38.0/24"}, "csrf_token": {e.csrf}}
	if resp, _ := e.post("/sites", browser, "Sec-Fetch-Site", "same-origin", "Origin", "null"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("same-origin browser form post: %d, want 303", resp.StatusCode)
	}
	if resp, _ := e.get("/login"); resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("Referrer-Policy %q: no-referrer makes browsers send Origin: null on form posts", resp.Header.Get("Referrer-Policy"))
	}
	resp := e.form("/sites", v)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/sites/") {
		t.Fatalf("create redirected to %q", resp.Header.Get("Location"))
	}
	// Flash shows once, from a cookie rather than the URL.
	_, body := e.get(resp.Header.Get("Location"))
	if !strings.Contains(body, "Site created") {
		t.Fatal("flash missing")
	}
	_, body = e.get(resp.Header.Get("Location"))
	if strings.Contains(body, "Site created") {
		t.Fatal("flash shown twice")
	}
	// Logout requires the token too, then ends the session.
	if resp, _ := e.post("/logout", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without token: %d", resp.StatusCode)
	}
	e.form("/logout", nil)
	if resp, _ := e.get("/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("session survived logout")
	}
}

func TestPagesRenderStatusFacts(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, pending, dev := e.fixture()
	pages := map[string][]string{
		"/":                 {"Agent reachable", "Configuration applied", "Local health", "Home", "configuration changed since last export"},
		"/sites":            {"Home", "Lake", "awaiting enrollment"},
		"/sites/" + home:    {"Agent reachable", "unknown", "Name resolution depends on this site for: phone", "TCP MSS clamp", "1380"},
		"/sites/" + pending: {"Issue enrollment token", "not enrolled"},
		"/devices":          {"phone", "10.0.0.2", "changed since export"},
		"/devices/" + dev:   {"10.0.0.2/32", "Internal resolvers", "data-replace-key", "Update profile (new key)", "data-export-stale", "Home"},
		"/devices/new":      {"A new key is generated in this browser", "Home", `name="dns_mode" value="none" checked`, `name="mtu"`, `name="search_domains"`, `name="keepalive" inputmode="numeric" value="25"`},
		"/audit":            {"device.enroll", "link.create"},
	}
	for path, wants := range pages {
		resp, body := e.get(path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", path, resp.StatusCode)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", path, w)
			}
		}
	}
	// Once exported, the dashboard's empty state reads unambiguously.
	m, err := e.svc.ProfileMaterialForExport(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RecordExport(context.Background(), dev, m.Revision); err != nil {
		t.Fatal(err)
	}
	if _, body := e.get("/"); !strings.Contains(body, "No devices need attention.") || !strings.Contains(body, "1 device</span>") {
		t.Error("dashboard empty state missing or miscounted")
	}
	// Pending sites are not offered for new-device access.
	if _, body := e.get("/devices/new"); strings.Contains(body, "Lake") {
		t.Error("pending site offered on new-device page")
	}
	// Device page warns about common-network collisions only for effective access.
	e.form("/devices/"+dev+"/links", url.Values{"site_id": {pending}})
	if _, body := e.get("/devices/" + dev); strings.Contains(body, "overlaps the common network 192.168.1.0/24") {
		t.Error("collision reported for a pending (non-effective) site")
	}
	if resp, _ := e.get("/sites/00000000-0000-0000-0000-000000000000"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing site: %d", resp.StatusCode)
	}
}

func TestLiveStatusAppearsAfterReport(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, _, dev := e.fixture()
	st, _ := e.svc.SiteStatus(context.Background(), home)
	err := e.svc.RecordStatus(context.Background(), &controller.Agent{SiteID: home}, &protocol.AgentStatus{
		AcceptedRevision: st.DesiredRevision, AppliedRevision: st.DesiredRevision, Healthy: true,
		Errors: []protocol.ComponentError{}, Peers: []protocol.PeerTelemetry{{DeviceID: dev, RxBytes: 2048, TxBytes: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := e.get("/sites/" + home + "/status")
	for _, w := range []string{"reachable", "healthy", "phone", "2.0 KiB", "does not prove LAN or DNS access"} {
		if !strings.Contains(body, w) {
			t.Errorf("status partial missing %q", w)
		}
	}
	if strings.Contains(body, "<html") {
		t.Error("partial rendered the full layout")
	}
}

func TestEnrollmentTokenShownOnce(t *testing.T) {
	e := newEnv(t)
	e.login()
	_, pending, _ := e.fixture()
	resp, body := e.post("/sites/"+pending+"/enrollment-token", url.Values{"csrf_token": {e.csrf}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d", resp.StatusCode)
	}
	tok := regexp.MustCompile(`plaite_[A-Za-z0-9_-]+`).FindString(body)
	if tok == "" || !strings.Contains(body, "plait-agent enroll -controller https://") {
		t.Fatal("token or enroll command missing")
	}
	_, again := e.get("/sites/" + pending)
	if strings.Contains(again, tok) {
		t.Fatal("token shown again")
	}
}

func TestControllerCAPublishedAndPinnedInEnrollCommand(t *testing.T) {
	e := newEnv(t)
	if resp, _ := e.get("/ca.pem"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/ca.pem without a generated CA: %d", resp.StatusCode)
	}
	const fp = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	e.ui.SetControllerCA([]byte("-----BEGIN CERTIFICATE-----\n"), fp)
	resp, body := e.get("/ca.pem") // public: no session
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("/ca.pem: %d %q", resp.StatusCode, body)
	}
	e.login()
	_, pending, _ := e.fixture()
	_, body = e.post("/sites/"+pending+"/enrollment-token", url.Values{"csrf_token": {e.csrf}})
	if !regexp.MustCompile(`-token plaite_[A-Za-z0-9_-]+ -ca-fingerprint ` + fp).MatchString(body) {
		t.Fatal("enroll command does not pin the controller CA")
	}
}

func TestConfirmationsAndPresetValidation(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, _, dev := e.fixture()
	e.form("/sites/"+home+"/disable", nil) // no confirm
	if st, _ := e.svc.State(context.Background()); !st.Sites[0].Enabled && st.Sites[0].ID == home {
		t.Fatal("site disabled without confirmation")
	}
	e.form("/devices/"+dev+"/retire", nil)
	st, _ := e.svc.State(context.Background())
	if d, _ := st.Device(dev); d.Retired {
		t.Fatal("device retired without confirmation")
	}
	e.form("/devices/"+dev+"/settings", url.Values{"dns_mode": {"internal"}, "dns_servers": {"10.13.37.53\n1.1.1.1"}})
	_, body := e.get("/devices/" + dev)
	if !strings.Contains(body, "Internal resolvers must be private addresses") {
		t.Fatal("mixed list accepted as internal preset")
	}
	e.form("/devices/"+dev+"/settings", url.Values{"dns_mode": {"custom"}, "dns_servers": {"10.13.37.53\n1.1.1.1"}})
	_, body = e.get("/devices/" + dev)
	if !strings.Contains(body, "mixed internal and public resolvers") {
		t.Fatal("mixed resolvers not labeled")
	}
	e.form("/devices/"+dev+"/settings", url.Values{"dns_mode": {"none"}, "dns_servers": {"10.13.37.53"}})
	st, _ = e.svc.State(context.Background())
	if d, _ := st.Device(dev); len(d.DNSServers) != 0 {
		t.Fatal("No tunnel DNS kept resolvers")
	}
	// PSK rotation needs explicit acknowledgment of the interruption.
	link := st.Links[0]
	e.form("/links/"+link.ID+"/rotate-psk", url.Values{"device_id": {dev}})
	st2, _ := e.svc.State(context.Background())
	if !st2.Links[0].PresharedKey.Equal(link.PresharedKey) {
		t.Fatal("PSK rotated without confirmation")
	}
	e.form("/links/"+link.ID+"/rotate-psk", url.Values{"device_id": {dev}, "confirm": {"yes"}})
	st2, _ = e.svc.State(context.Background())
	if st2.Links[0].PresharedKey.Equal(link.PresharedKey) {
		t.Fatal("confirmed PSK rotation did nothing")
	}
}

func TestNoSecretsInPages(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, _, dev := e.fixture()
	m, err := e.svc.ProfileMaterial(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	psk := m.Peers[0].PresharedKey.String()
	for _, path := range []string{"/", "/sites", "/sites/" + home, "/sites/" + home + "/status", "/devices", "/devices/new", "/devices/" + dev, "/audit"} {
		_, body := e.get(path)
		if strings.Contains(body, psk) {
			t.Errorf("%s contains a PSK", path)
		}
		// No page asks for a private key or a device's existing key.
		if strings.Contains(body, "data-private-key") || strings.Contains(body, `type="password"`) || strings.Contains(body, `name="public_key"`) {
			t.Errorf("%s has a key input", path)
		}
	}
}

// TestVendoredChecksums fails if an embedded vendored file differs from the
// checksum recorded in VENDOR.md.
func TestVendoredChecksums(t *testing.T) {
	doc, err := fs.ReadFile(staticFS, "static/vendor/VENDOR.md")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^([0-9a-f]{64})  (\S+)$`)
	matches := re.FindAllStringSubmatch(string(doc), -1)
	if len(matches) != 3 {
		t.Fatalf("expected 3 checksums in VENDOR.md, found %d", len(matches))
	}
	for _, m := range matches {
		b, err := fs.ReadFile(staticFS, "static/vendor/"+m[2])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != m[1] {
			t.Errorf("%s does not match VENDOR.md", m[2])
		}
	}
	e := newEnv(t)
	resp, _ := e.get("/static/vendor/x25519.js")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("static: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestSiteGatewayAccessPorts(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, _, _ := e.fixture()
	v := url.Values{"name": {"Home"}, "endpoint_host": {"home.example.net"}, "listen_port": {"51111"}, "mtu": {"1420"},
		"egress_interface": {"eth0"}, "subnets": {"10.13.37.0/24"}, "gateway_tcp_ports": {"2222, 22"}}
	e.form("/sites/"+home, v)
	st, _ := e.svc.State(context.Background())
	if s, _ := st.Site(home); !slices.Equal(s.GatewayTCPPorts, []uint16{22, 2222}) {
		t.Fatalf("stored ports %v", s.GatewayTCPPorts)
	}
	if _, body := e.get("/sites/" + home); !strings.Contains(body, `name="gateway_tcp_ports" inputmode="numeric" value="22,2222"`) {
		t.Fatal("form does not show the stored ports")
	}
	v.Set("gateway_tcp_ports", "ssh")
	v.Set("csrf_token", e.csrf)
	e.post("/sites/"+home, v)
	st, _ = e.svc.State(context.Background())
	if s, _ := st.Site(home); !slices.Equal(s.GatewayTCPPorts, []uint16{22, 2222}) {
		t.Fatalf("invalid input changed the ports to %v", s.GatewayTCPPorts)
	}
}

func TestDeleteDevice(t *testing.T) {
	e := newEnv(t)
	e.login()
	_, _, dev := e.fixture()
	if _, body := e.get("/devices/" + dev); !strings.Contains(body, "disable or retire it first") {
		t.Fatal("active device offered deletion")
	}
	e.form("/devices/"+dev+"/retire", url.Values{"confirm": {"yes"}})
	e.form("/devices/"+dev+"/delete", url.Values{"force": {"yes"}}) // no confirm
	if st, _ := e.svc.State(context.Background()); len(st.Devices) != 1 {
		t.Fatal("device deleted without confirmation")
	}
	if _, body := e.get("/devices/" + dev); !strings.Contains(body, "Delete device") || !strings.Contains(body, "Delete anyway") {
		t.Fatal("retired device with an unapplied removal lacks delete and override")
	}
	resp := e.form("/devices/"+dev+"/delete", url.Values{"confirm": {"yes"}, "force": {"yes"}})
	if loc := resp.Header.Get("Location"); loc != "/devices" {
		t.Fatalf("redirect after delete: %q", loc)
	}
	if _, body := e.get("/devices"); !strings.Contains(body, "Deleted phone. Its address 10.0.0.2 is free") {
		t.Fatal("no confirmation after delete")
	}
	if st, _ := e.svc.State(context.Background()); len(st.Devices) != 0 || len(st.Links) != 0 {
		t.Fatalf("device or links remain: %d devices, %d links", len(st.Devices), len(st.Links))
	}
}

func TestAuditLinksOnlyLiveTargets(t *testing.T) {
	e := newEnv(t)
	e.login()
	home, _, dev := e.fixture()
	e.form("/devices/"+dev+"/retire", url.Values{"confirm": {"yes"}})
	_, body := e.get("/audit")
	if !strings.Contains(body, `href="/devices/`+dev+`"`) || !strings.Contains(body, `href="/sites/`+home+`"`) {
		t.Fatal("existing targets not linked")
	}
	e.form("/devices/"+dev+"/delete", url.Values{"confirm": {"yes"}, "force": {"yes"}})
	_, body = e.get("/audit")
	if strings.Contains(body, `href="/devices/`+dev+`"`) || !strings.Contains(body, "(deleted)") {
		t.Fatal("deleted device still linked from the audit log")
	}
	if !strings.Contains(body, `href="/sites/`+home+`"`) {
		t.Fatal("site link lost")
	}
}
