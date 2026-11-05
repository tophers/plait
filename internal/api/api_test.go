package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"slices"
	"testing"
	"time"

	"plait/internal/agent"
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

const adminPassword = "correct horse battery"

// syncBuffer is a goroutine-safe log sink so tests can scan for secrets.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t      *testing.T
	dir    string
	st     *store.Store
	svc    *controller.Service
	srv    *httptest.Server
	logs   *syncBuffer
	clock  time.Time
	mu     sync.Mutex
	csrf   string
	client *http.Client
	sealer *secrets.Sealer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), logs: &syncBuffer{}, clock: time.Now().UTC().Truncate(time.Second)} // real time: the cookie jar expires cookies by the wall clock
	st, err := store.Open(context.Background(), filepath.Join(e.dir, "plaitd.db"))
	if err != nil {
		t.Fatal(err)
	}
	e.sealer, _ = secrets.NewSealer(bytes.Repeat([]byte{7}, 32))
	e.start(st)
	if err := e.svc.CreateAdmin(context.Background(), "admin", adminPassword); err != nil {
		t.Fatal(err)
	}
	e.login()
	return e
}

// start (re)creates the service and HTTP server on st, as a controller
// restart would.
func (e *env) start(st *store.Store) {
	if e.srv != nil {
		e.srv.Close()
	}
	e.st = st
	pool, _ := model.ParsePool("10.0.0.0/24", nil)
	svc, err := controller.New(st, pool, e.sealer)
	if err != nil {
		e.t.Fatal(err)
	}
	svc.SetClock(e.now)
	e.svc = svc
	e.srv = httptest.NewTLSServer(New(svc, slog.New(slog.NewTextHandler(e.logs, nil))).Handler())
	e.t.Cleanup(func() { e.srv.Close(); st.Close() })
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Transport: e.srv.Client().Transport, Jar: jar}
}

// anon returns a client with no session cookies.
func (e *env) anon() *http.Client { return &http.Client{Transport: e.srv.Client().Transport} }

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func (e *env) login() {
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	e.do("POST", "/api/v1/admin/login", map[string]string{"username": "admin", "password": adminPassword}, 200, &out)
	e.csrf = out.CSRF
}

// do sends an admin request with the CSRF header and checks the status.
func (e *env) do(method, path string, body any, want int, out any) {
	e.t.Helper()
	resp := e.raw(method, path, body, map[string]string{"X-CSRF-Token": e.csrf})
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("%s %s: decode: %v: %s", method, path, err, data)
		}
	}
}

func (e *env) raw(method, path string, body any, headers map[string]string) *http.Response {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) agentClient(cred string) *agent.Client {
	c := agent.NewClient(e.srv.URL, cred)
	c.HTTP = e.anon()
	return c
}

type site struct {
	ID   string
	priv wg.Key
	pub  wg.Key
	cred string
}

// enrollSite creates a pending site and enrolls a gateway for it via the API.
func (e *env) enrollSite(name, subnet string) *site {
	e.t.Helper()
	var sv siteView
	e.do("POST", "/api/v1/admin/sites", map[string]any{
		"name": name, "endpoint_host": strings.ToLower(name) + ".example.net", "egress_interface": "eth0", "subnets": []string{subnet},
	}, 201, &sv)
	if !sv.Pending {
		e.t.Fatal("new site without key should be pending enrollment")
	}
	var tok struct {
		Token string `json:"token"`
	}
	e.do("POST", "/api/v1/admin/sites/"+sv.ID+"/enrollment-token", nil, 201, &tok)
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()
	var enr enrollResponse
	e.do("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": pub}, 200, &enr)
	if enr.SiteID != sv.ID || enr.Credential == "" {
		e.t.Fatalf("enroll response: %+v", enr)
	}
	return &site{ID: sv.ID, priv: priv, pub: pub, cred: enr.Credential}
}

func (e *env) enrollDevice(name string) (string, wg.Key) {
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()
	var dv deviceView
	e.do("POST", "/api/v1/admin/devices", map[string]any{"name": name, "public_key": pub}, 201, &dv)
	return dv.ID, priv
}

func (e *env) link(siteID, deviceID string) string {
	var out map[string]string
	e.do("POST", "/api/v1/admin/links", map[string]any{"site_id": siteID, "device_id": deviceID}, 201, &out)
	return out["id"]
}

func (e *env) report(s *site, accepted, applied int64, healthy bool) {
	e.t.Helper()
	err := e.agentClient(s.cred).Report(context.Background(), &protocol.AgentStatus{
		SiteID: s.ID, AcceptedRevision: accepted, AppliedRevision: applied, ObservedAt: e.now(),
		AgentVersion: "test", Healthy: healthy, Errors: []protocol.ComponentError{},
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) siteStatus(id string) controller.SiteStatus {
	var st controller.SiteStatus
	e.do("GET", "/api/v1/admin/sites/"+id+"/status", nil, 200, &st)
	return st
}

// --- tests ---

func TestAdminAuthentication(t *testing.T) {
	e := newEnv(t)
	anon := e.anon()
	resp, _ := anon.Get(e.srv.URL + "/api/v1/admin/sites")
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated list: %d", resp.StatusCode)
	}
	for i := 0; i < 10; i++ {
		resp := e.raw("POST", "/api/v1/admin/login", map[string]string{"username": "admin", "password": "wrong password!"}, nil)
		if resp.StatusCode != 401 {
			t.Fatalf("bad login %d: %d", i, resp.StatusCode)
		}
	}
	resp = e.raw("POST", "/api/v1/admin/login", map[string]string{"username": "admin", "password": adminPassword}, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("login after repeated failures: %d, want 429", resp.StatusCode)
	}

	// Session expiry: idle timeout ends the session.
	e.do("GET", "/api/v1/admin/session", nil, 200, nil)
	e.advance(controller.SessionIdle + time.Minute)
	e.do("GET", "/api/v1/admin/session", nil, 401, nil)
}

func TestCSRFAndOrigin(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{"name": "Home", "endpoint_host": "home.example.net", "egress_interface": "eth0", "subnets": []string{"10.13.37.0/24"}}
	if r := e.raw("POST", "/api/v1/admin/sites", body, nil); r.StatusCode != 403 {
		t.Fatalf("missing CSRF token: %d", r.StatusCode)
	}
	if r := e.raw("POST", "/api/v1/admin/sites", body, map[string]string{"X-CSRF-Token": e.csrf, "Origin": "https://evil.example"}); r.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", r.StatusCode)
	}
	e.do("POST", "/api/v1/admin/sites", body, 201, nil)
	// An agent credential is never administrator access.
	s := e.enrollSite("Emerald", "10.15.0.0/24")
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/admin/sites", nil)
	req.Header.Set("Authorization", "Bearer "+s.cred)
	resp, _ := e.anon().Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("agent credential on admin API: %d", resp.StatusCode)
	}
}

func TestMalformedRequests(t *testing.T) {
	e := newEnv(t)
	e.do("POST", "/api/v1/admin/sites", map[string]any{"name": "X", "bogus": 1}, 400, nil)
	r := e.raw("POST", "/api/v1/admin/devices", nil, map[string]string{"X-CSRF-Token": e.csrf, "Content-Type": "text/plain"})
	if r.StatusCode != 400 {
		t.Fatalf("wrong content type: %d", r.StatusCode)
	}
	e.do("POST", "/api/v1/admin/sites", map[string]any{"name": "Bad", "endpoint_host": "h", "egress_interface": "eth0", "subnets": []string{"0.0.0.0/0"}}, 400, nil)
}

func TestEnrollmentTokens(t *testing.T) {
	e := newEnv(t)
	var sv siteView
	e.do("POST", "/api/v1/admin/sites", map[string]any{"name": "Home", "endpoint_host": "h.example", "egress_interface": "eth0", "subnets": []string{"10.13.37.0/24"}}, 201, &sv)
	var tok struct{ Token string }
	e.do("POST", "/api/v1/admin/sites/"+sv.ID+"/enrollment-token", map[string]int{"ttl_seconds": 600}, 201, &tok)
	priv, _ := wg.GeneratePrivateKey()
	pub, _ := priv.PublicKey()

	e.advance(11 * time.Minute)
	e.do("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": pub}, 403, nil)

	e.do("POST", "/api/v1/admin/sites/"+sv.ID+"/enrollment-token", nil, 201, &tok)
	e.do("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": pub}, 200, nil)
	e.do("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": pub}, 403, nil) // single use

	// Concurrent use of one token: exactly one wins.
	e.do("POST", "/api/v1/admin/sites/"+sv.ID+"/enrollment-token", nil, 201, &tok)
	var wg2 sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			p, _ := wg.GeneratePrivateKey()
			pk, _ := p.PublicKey()
			r := e.raw("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": pk}, nil)
			codes <- r.StatusCode
		}()
	}
	wg2.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent enrollments succeeded with one token", ok)
	}
}

func TestSiteScopedCredentials(t *testing.T) {
	e := newEnv(t)
	home := e.enrollSite("Home", "10.13.37.0/24")
	emerald := e.enrollSite("Emerald", "10.15.0.0/24")
	dev, _ := e.enrollDevice("phone")
	e.link(home.ID, dev)
	e.link(emerald.ID, dev)

	snap, err := e.agentClient(home.cred).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.SiteID != home.ID || !snap.Interface.PublicKey.Equal(home.pub) || len(snap.Peers) != 1 {
		t.Fatalf("home snapshot: %+v", snap)
	}

	// A credential cannot report status for another site.
	err = e.agentClient(home.cred).Report(context.Background(), &protocol.AgentStatus{SiteID: emerald.ID, AppliedRevision: 1, Errors: []protocol.ComponentError{}})
	if err == nil {
		t.Fatal("cross-site status accepted")
	}
	if st := e.siteStatus(emerald.ID); st.Reachability != "unknown" {
		t.Fatalf("emerald status changed by home's credential: %+v", st)
	}

	// Malformed and tampered credentials fail.
	for _, bad := range []string{"", "garbage", home.cred + "x", strings.Replace(home.cred, "plaita", "plaite", 1)} {
		if _, err := e.agentClient(bad).Fetch(context.Background()); err == nil {
			t.Fatalf("credential %q accepted", bad)
		}
	}

	// Rotation: the new credential works; the old one works only during
	// overlap, and no further rotation is accepted until it ends.
	rotate := func(cred string) (*http.Response, error) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/agent/credential/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+cred)
		return e.anon().Do(req)
	}
	var rot struct{ Credential string }
	resp, err := rotate(home.cred)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("rotate: %v %d", err, resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&rot)
	for _, cred := range []string{home.cred, rot.Credential} {
		if resp, err := rotate(cred); err != nil || resp.StatusCode != 429 {
			t.Fatalf("rotation during overlap: %v %v", err, resp.Status)
		}
	}
	if _, err := e.agentClient(home.cred).Fetch(context.Background()); err != nil {
		t.Fatal("old credential rejected during overlap")
	}
	e.advance(controller.DefaultCredentialOverlap + time.Second)
	if _, err := e.agentClient(home.cred).Fetch(context.Background()); err == nil {
		t.Fatal("old credential accepted after overlap")
	}
	if _, err := e.agentClient(rot.Credential).Fetch(context.Background()); err != nil {
		t.Fatalf("new credential: %v", err)
	}
	if resp, err := rotate(rot.Credential); err != nil || resp.StatusCode != 200 {
		t.Fatalf("rotation after overlap: %v %v", err, resp.Status)
	}

	// Administrative revocation blocks access.
	e.do("POST", "/api/v1/admin/sites/"+home.ID+"/credentials/revoke", nil, 204, nil)
	if _, err := e.agentClient(rot.Credential).Fetch(context.Background()); err == nil {
		t.Fatal("revoked credential accepted")
	}
	// Re-enrollment with a new gateway key requires a fresh admin-issued token.
	var tok struct{ Token string }
	e.do("POST", "/api/v1/admin/sites/"+home.ID+"/enrollment-token", nil, 201, &tok)
	newPriv, _ := wg.GeneratePrivateKey()
	newPub, _ := newPriv.PublicKey()
	var enr enrollResponse
	e.do("POST", "/api/v1/agent/enroll", map[string]any{"token": tok.Token, "public_key": newPub}, 200, &enr)
	snap, err = e.agentClient(enr.Credential).Fetch(context.Background())
	if err != nil || !snap.Interface.PublicKey.Equal(newPub) {
		t.Fatalf("re-enrolled snapshot: %v", err)
	}
	var m protocol.ProfileMaterial
	e.do("GET", "/api/v1/admin/devices/"+dev+"/profile-material", nil, 200, &m)
	for _, p := range m.Peers {
		if p.SiteID == home.ID && !p.PublicKey.Equal(newPub) {
			t.Fatal("device profile not updated with replaced gateway key")
		}
	}
}

func TestStatusAndPendingRevocation(t *testing.T) {
	e := newEnv(t)
	home := e.enrollSite("Home", "10.13.37.0/24")
	dev, _ := e.enrollDevice("phone")
	e.link(home.ID, dev)

	st := e.siteStatus(home.ID)
	if st.Reachability != "unknown" || st.Health != "unknown" || !st.ChangePending {
		t.Fatalf("before any report: %+v", st)
	}
	desired := st.DesiredRevision
	e.report(home, desired, desired, true)
	st = e.siteStatus(home.ID)
	if st.Reachability != "reachable" || st.Health != "healthy" || st.ChangePending || st.AppliedRevision != desired {
		t.Fatalf("after report: %+v", st)
	}

	// Revoke the device: pending until the site acknowledges.
	var dv deviceView
	e.do("POST", "/api/v1/admin/devices/"+dev+"/disable", nil, 200, &dv)
	if !dv.RevocationPending {
		t.Fatalf("revocation not shown pending: %+v", dv)
	}
	snap, _ := e.agentClient(home.cred).Fetch(context.Background())
	if len(snap.Peers) != 0 || snap.Revision != desired+1 {
		t.Fatalf("disabled device still in snapshot: %+v", snap)
	}
	e.report(home, desired+1, desired, false) // accepted, not yet applied
	e.do("GET", "/api/v1/admin/devices/"+dev, nil, 200, &dv)
	if !dv.RevocationPending {
		t.Fatal("revocation shown complete before applied")
	}
	e.report(home, desired+1, desired+1, true)
	e.do("GET", "/api/v1/admin/devices/"+dev, nil, 200, &dv)
	if dv.RevocationPending {
		t.Fatal("revocation still pending after acknowledgment")
	}

	// Older acknowledgments never overwrite newer progress; claims beyond
	// desired are not recorded as applied.
	e.report(home, desired+1, desired, true)
	e.report(home, desired+5, desired+5, true)
	st = e.siteStatus(home.ID)
	if st.AppliedRevision != desired+1 || !st.AheadOfDesired {
		t.Fatalf("applied regression/overclaim: %+v", st)
	}

	// Disconnected agent: stale, health unknown.
	e.advance(controller.StaleAfter + time.Second)
	st = e.siteStatus(home.ID)
	if st.Reachability != "stale" || st.Health != "unknown" {
		t.Fatalf("stale agent: %+v", st)
	}

	// Controller restart: live state is unknown; acknowledgments persist.
	e.start(e.st)
	e.login()
	st = e.siteStatus(home.ID)
	if st.Reachability != "unknown" || st.Health != "unknown" || st.AppliedRevision != desired+1 {
		t.Fatalf("after restart: %+v", st)
	}

	// Site drain: explicit empty peer set, credential still valid.
	e.do("POST", "/api/v1/admin/devices/"+dev+"/enable", nil, 200, nil)
	e.do("POST", "/api/v1/admin/sites/"+home.ID+"/disable", nil, 200, nil)
	snap, err := e.agentClient(home.cred).Fetch(context.Background())
	if err != nil || snap.Peers == nil || len(snap.Peers) != 0 {
		t.Fatalf("drained snapshot: %v %+v", err, snap)
	}

	// Inactive device profile export is refused.
	e.do("POST", "/api/v1/admin/devices/"+dev+"/retire", nil, 200, nil)
	e.do("GET", "/api/v1/admin/devices/"+dev+"/profile-material", nil, 409, nil)
}

func TestSecretsStayOutOfLogsStatusAndAudit(t *testing.T) {
	e := newEnv(t)
	home := e.enrollSite("Home", "10.13.37.0/24")
	dev, devPriv := e.enrollDevice("phone")
	e.link(home.ID, dev)
	var m protocol.ProfileMaterial
	e.do("GET", "/api/v1/admin/devices/"+dev+"/profile-material", nil, 200, &m)
	e.report(home, 1, 1, true)
	var tok struct{ Token string }
	e.do("POST", "/api/v1/admin/sites/"+home.ID+"/enrollment-token", nil, 201, &tok)
	e.raw("POST", "/api/v1/admin/login", map[string]string{"username": "admin", "password": "not-the-password"}, nil)

	var status, audit, creds json.RawMessage
	e.do("GET", "/api/v1/admin/sites/"+home.ID+"/status", nil, 200, &status)
	e.do("GET", "/api/v1/admin/audit?limit=500", nil, 200, &audit)
	e.do("GET", "/api/v1/admin/sites/"+home.ID+"/credentials", nil, 200, &creds)

	secretsList := map[string]string{
		"psk":               m.Peers[0].PresharedKey.String(),
		"agent credential":  home.cred,
		"credential secret": home.cred[strings.LastIndex(home.cred, "_")+1:],
		"enrollment token":  tok.Token,
		"gateway private":   home.priv.String(),
		"device private":    devPriv.String(),
		"admin password":    adminPassword,
		"bad password":      "not-the-password",
	}
	haystacks := map[string]string{"logs": e.logs.String(), "status": string(status), "audit": string(audit), "credentials": string(creds)}
	for hn, h := range haystacks {
		for sn, s := range secretsList {
			if strings.Contains(h, s) {
				t.Errorf("%s contains %s", hn, sn)
			}
		}
	}
	if !strings.Contains(string(audit), "device.profile_material") {
		t.Error("profile material access not audited")
	}
}

func TestBackupRestoreRecovery(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	home := e.enrollSite("Home", "10.13.37.0/24")
	dev, _ := e.enrollDevice("phone")
	e.link(home.ID, dev)
	backup := filepath.Join(e.dir, "backup.db")
	if err := e.svc.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}

	// After the backup: revoke the device; the agent applies it.
	e.do("POST", "/api/v1/admin/devices/"+dev+"/disable", nil, 200, nil)
	snap, _ := e.agentClient(home.cred).Fetch(ctx)
	revoked := snap.Revision
	e.report(home, revoked, revoked, true)

	// Disaster: restore the older database. It still has the device enabled.
	st, err := store.Open(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	e.start(st)
	if err := e.svc.BeginRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	e.login()
	if _, err := e.agentClient(home.cred).Fetch(ctx); err == nil {
		t.Fatal("desired state served during recovery")
	}
	// Agents still report, revealing they are ahead of the restored state.
	e.report(home, revoked, revoked, true)
	if s := e.siteStatus(home.ID); !s.AheadOfDesired {
		t.Fatalf("agent ahead not detected: %+v", s)
	}

	// The administrator re-applies the lost revocation, then completes recovery.
	e.do("POST", "/api/v1/admin/devices/"+dev+"/disable", nil, 200, nil)
	if err := e.svc.CompleteRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err = e.agentClient(home.cred).Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision <= revoked {
		t.Fatalf("revision %d not advanced past agent's %d", snap.Revision, revoked)
	}
	if len(snap.Peers) != 0 {
		t.Fatal("revoked device re-enabled by restore")
	}
}

func TestEncryptionKeyRecovery(t *testing.T) {
	e := newEnv(t)
	home := e.enrollSite("Home", "10.13.37.0/24")
	dev, _ := e.enrollDevice("phone")
	e.link(home.ID, dev)
	before, _ := e.agentClient(home.cred).Fetch(context.Background())

	// Same key (restored from its separate backup): PSKs decrypt unchanged.
	e.start(e.st)
	after, err := e.agentClient(home.cred).Fetch(context.Background())
	if err != nil || !after.Peers[0].PresharedKey.Equal(before.Peers[0].PresharedKey) {
		t.Fatalf("PSK changed across restart with the same key: %v", err)
	}

	// Wrong key: the controller refuses to serve rather than emit garbage.
	wrong, _ := secrets.NewSealer(bytes.Repeat([]byte{9}, 32))
	pool, _ := model.ParsePool("10.0.0.0/24", nil)
	svc, _ := controller.New(e.st, pool, wrong)
	if _, err := svc.SiteSnapshot(context.Background(), home.ID); err == nil {
		t.Fatal("snapshot compiled with the wrong encryption key")
	}
}

// A device can be enrolled with its client settings, so its first profile is
// complete; invalid settings reject the enrollment without creating a device.
func TestEnrollDeviceWithSettings(t *testing.T) {
	e := newEnv(t)
	pub := func() wg.Key {
		priv, _ := wg.GeneratePrivateKey()
		p, _ := priv.PublicKey()
		return p
	}
	var dv deviceView
	e.do("POST", "/api/v1/admin/devices", map[string]any{"name": "phone", "public_key": pub(),
		"mtu": 1380, "search_domains": []string{"home.lan", "cabin.lan"}, "dns_servers": []string{"10.13.37.53", "10.13.38.53"}}, 201, &dv)
	if dv.ClientMTU != 1380 || !slices.Equal(dv.SearchDomains, []string{"home.lan", "cabin.lan"}) || len(dv.DNSServers) != 2 || dv.DNSServers[1].String() != "10.13.38.53" {
		t.Fatalf("settings not stored: %+v", dv)
	}
	var m protocol.ProfileMaterial
	e.do("GET", "/api/v1/admin/devices/"+dv.ID+"/profile-material", nil, 200, &m)
	if m.MTU != 1380 || !slices.Equal(m.SearchDomains, []string{"home.lan", "cabin.lan"}) || len(m.DNSServers) != 2 {
		t.Fatalf("profile material lacks settings: %+v", m)
	}

	for _, bad := range []map[string]any{
		{"dns_servers": []string{"not-an-ip"}},
		{"mtu": 100},
		{"search_domains": []string{"bad domain"}},
		{"search_domains": []string{"home.lan", "HOME.lan"}},
	} {
		bad["name"], bad["public_key"] = "tablet", pub()
		e.do("POST", "/api/v1/admin/devices", bad, 400, nil)
	}
	var list []deviceView
	e.do("GET", "/api/v1/admin/devices", nil, 200, &list)
	if len(list) != 1 {
		t.Fatalf("rejected enrollments created devices: %d", len(list))
	}
}

// Deleting a device frees its address, but only once it is inactive and every
// linked site has applied its removal, unless forced. Audit history remains.
func TestDeleteDeviceReclaimsAddress(t *testing.T) {
	e := newEnv(t)
	home := e.enrollSite("Home", "10.13.37.0/24")
	dev, _ := e.enrollDevice("phone")
	e.link(home.ID, dev)
	var dv deviceView
	e.do("GET", "/api/v1/admin/devices/"+dev, nil, 200, &dv)
	addr := dv.Address
	desired := e.siteStatus(home.ID).DesiredRevision
	e.report(home, desired, desired, true)

	e.do("DELETE", "/api/v1/admin/devices/"+dev, nil, 400, nil) // still active
	e.do("POST", "/api/v1/admin/devices/"+dev+"/retire", nil, 200, nil)
	e.do("DELETE", "/api/v1/admin/devices/"+dev, nil, 400, nil) // Home has not applied the removal
	e.report(home, desired+1, desired+1, true)
	e.do("DELETE", "/api/v1/admin/devices/"+dev, nil, 204, nil)
	e.do("GET", "/api/v1/admin/devices/"+dev, nil, 404, nil)
	if st := e.siteStatus(home.ID); st.DesiredRevision != desired+1 {
		t.Fatalf("deleting an inactive device changed the site: desired %d, want %d", st.DesiredRevision, desired+1)
	}

	next, _ := e.enrollDevice("tablet")
	e.do("GET", "/api/v1/admin/devices/"+next, nil, 200, &dv)
	if dv.Address != addr {
		t.Fatalf("address not reclaimed: got %s, want %s", dv.Address, addr)
	}

	// A gateway that never reports again can be overridden.
	e.link(home.ID, next)
	e.do("POST", "/api/v1/admin/devices/"+next+"/disable", nil, 200, nil)
	e.do("DELETE", "/api/v1/admin/devices/"+next, nil, 400, nil)
	e.do("DELETE", "/api/v1/admin/devices/"+next+"?force=true", nil, 204, nil)

	var audit []struct {
		Action   string `json:"action"`
		TargetID string `json:"target_id"`
	}
	e.do("GET", "/api/v1/admin/audit", nil, 200, &audit)
	var deletes, enrolls int
	for _, a := range audit {
		if a.TargetID == dev {
			switch a.Action {
			case "device.delete":
				deletes++
			case "device.enroll":
				enrolls++
			}
		}
	}
	if deletes != 1 || enrolls != 1 {
		t.Fatalf("audit history for deleted device: %d deletes, %d enrolls", deletes, enrolls)
	}
}
