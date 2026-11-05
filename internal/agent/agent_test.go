package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"plait/internal/protocol"
)

func TestCacheRoundTripAndCorruption(t *testing.T) {
	c := &Cache{Dir: filepath.Join(t.TempDir(), "state")}
	if _, err := c.LoadDesired(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty cache: %v", err)
	}
	key, created, err := c.LoadOrCreateKey()
	if err != nil || !created {
		t.Fatal(err)
	}
	again, created, err := c.LoadOrCreateKey()
	if err != nil || created || !again.Equal(key) {
		t.Fatal("gateway key not stable across loads")
	}
	if fi, _ := os.Stat(filepath.Join(c.Dir, "gateway.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("gateway.key mode %o", fi.Mode().Perm())
	}

	snap := snapshot(key, 3, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	if err := c.StoreDesired(snap); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadDesired()
	if err != nil || got.Revision != 3 || len(got.Peers) != 1 {
		t.Fatalf("load: %v %+v", err, got)
	}

	path := filepath.Join(c.Dir, "desired.json")
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 0x01
	os.WriteFile(path, raw, 0o600)
	if _, err := c.LoadDesired(); !errors.Is(err, ErrCorruptCache) {
		t.Fatalf("corruption not detected: %v", err)
	}
}

func TestSupersedes(t *testing.T) {
	gwKey := newPeer(t).priv
	a := snapshot(gwKey, 5, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	if ok, err := Supersedes(nil, a); !ok || err != nil {
		t.Fatal("first snapshot not accepted")
	}
	older := snapshot(gwKey, 4, nil)
	if _, err := Supersedes(a, older); !errors.Is(err, ErrRevisionRegression) {
		t.Fatalf("regression: %v", err)
	}
	same := *a
	if ok, err := Supersedes(a, &same); ok || err != nil {
		t.Fatal("identical revision treated as change")
	}
	conflict := snapshot(gwKey, 5, nil)
	if _, err := Supersedes(a, conflict); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("conflict: %v", err)
	}
}

func TestValidatorRejectsForeignIdentity(t *testing.T) {
	gw := newPeer(t)
	v := Validator{SiteID: "site-1", PublicKey: gw.pub}
	snap := snapshot(gw.priv, 1, nil)
	if err := v.Check(snap); err != nil {
		t.Fatal(err)
	}
	other := snapshot(newPeer(t).priv, 1, nil)
	if err := v.Check(other); err == nil {
		t.Fatal("unexpected gateway key accepted")
	}
	snap.SiteID = "site-2"
	if err := v.Check(snap); err == nil {
		t.Fatal("other site's snapshot accepted")
	}
}

func TestAgentDoesNotRollBackRevocation(t *testing.T) {
	r, h, gw := newRecon(t)
	pub, _ := gw.PublicKey()
	a := &Agent{Cache: &Cache{Dir: t.TempDir()}, Validator: Validator{SiteID: "site-1", PublicKey: pub}, Recon: r, Log: slog.New(slog.DiscardHandler)}
	ctx := context.Background()
	peer := newPeer(t)

	if _, err := a.Accept(snapshot(gw, 1, map[string]peerKeys{"10.0.0.4": peer})); err != nil {
		t.Fatal(err)
	}
	if res, _ := a.ReconcileCached(ctx); !res.Verified {
		t.Fatal(res.Errors)
	}

	// Revision 2 revokes the peer but the firewall fails to apply.
	h.applyErr = errors.New("boom")
	if _, err := a.Accept(snapshot(gw, 2, nil)); err != nil {
		t.Fatal(err)
	}
	a.ReconcileCached(ctx)

	// Simulate an agent restart: state comes back from the cache only.
	b := &Agent{Cache: a.Cache, Validator: a.Validator, Recon: r, Log: a.Log}
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	b.ReconcileCached(ctx)
	if len(h.dev.Peers) != 0 {
		t.Fatal("revoked peer resurrected after restart")
	}
	if b.applied.Revision != 1 {
		t.Fatalf("applied revision = %d, want 1 (revision 2 never verified)", b.applied.Revision)
	}
	h.applyErr = nil
	b.ReconcileCached(ctx)
	if b.applied.Revision != 2 {
		t.Fatalf("applied revision = %d after recovery", b.applied.Revision)
	}
}

func TestClientFetchFailuresAreNeverEmpty(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"html": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>"))
		},
		"malformed": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"schema_version":1,`))
		},
		"missing peers": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"schema_version":1,"site_id":"s","revision":2,"interface":{"name":"plait0","public_key":"` +
				newPeer(t).pub.String() + `","listen_port":51111,"mtu":1420},"network":{"client_pool":"10.0.0.0/24","egress_interface":"eth0","lan_prefixes":[],"masquerade":true}}`))
		},
		"future schema": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"schema_version":2,"peers":[]}`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			snap, err := NewClient(srv.URL, "tok").Fetch(context.Background())
			if err == nil {
				t.Fatalf("got snapshot %+v, want error", snap)
			}
		})
	}
}

func TestClientSendsBearer(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	if err := NewClient(srv.URL, "secret-token").Report(context.Background(), &protocol.AgentStatus{}); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", auth)
	}
}

func TestClientRereadsCredentialFile(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		w.WriteHeader(204)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "agent.credential")
	if err := WriteCredential(path, "old"); err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.URL, "old")
	c.TokenFile = path
	ctx := context.Background()
	c.Report(ctx, &protocol.AgentStatus{})
	// What `plait-agent rotate-credential` does from another process.
	if err := WriteCredential(path, "new"); err != nil {
		t.Fatal(err)
	}
	c.Report(ctx, &protocol.AgentStatus{})
	if want := []string{"Bearer old", "Bearer new"}; !slices.Equal(auth, want) {
		t.Fatalf("Authorization = %q, want %q", auth, want)
	}
	os.Chmod(path, 0o644)
	if err := c.Report(ctx, &protocol.AgentStatus{}); err == nil || len(auth) != 2 {
		t.Fatalf("loose credential file used: err %v", err)
	}
}

func TestPollRejectsBadSnapshotAndKeepsCache(t *testing.T) {
	r, _, gw := newRecon(t)
	pub, _ := gw.PublicKey()
	a := &Agent{Cache: &Cache{Dir: t.TempDir()}, Validator: Validator{SiteID: "site-1", PublicKey: pub}, Recon: r, Log: slog.New(slog.DiscardHandler)}
	good := snapshot(gw, 3, map[string]peerKeys{"10.0.0.4": newPeer(t)})
	if _, err := a.Accept(good); err != nil {
		t.Fatal(err)
	}

	serve := func(s *protocol.SiteSnapshot) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s)
		}))
	}
	srv := serve(snapshot(gw, 2, nil)) // regression
	defer srv.Close()
	a.Client = NewClient(srv.URL, "tok")
	if err := a.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := a.Status()
	if st.AcceptedRevision != 3 || st.Healthy || len(st.Errors) == 0 || st.Errors[len(st.Errors)-1].Code != "snapshot-rejected" {
		t.Fatalf("status = %+v", st)
	}
	cached, _ := a.Cache.LoadDesired()
	if cached.Revision != 3 {
		t.Fatalf("cache replaced by rejected snapshot: revision %d", cached.Revision)
	}

	srv2 := serve(snapshot(gw, 4, nil))
	defer srv2.Close()
	a.Client = NewClient(srv2.URL, "tok")
	if err := a.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.rejected != nil || a.desired.Revision != 4 {
		t.Fatal("newer snapshot not accepted")
	}
}

func TestHTTPErrorsAreTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	_, err := NewClient(srv.URL, "tok").Fetch(context.Background())
	var he *HTTPError
	if !errors.As(err, &he) || he.Code != 503 {
		t.Fatalf("err = %v, want *HTTPError 503", err)
	}
	srv.Close()
	_, err = NewClient(srv.URL, "tok").Fetch(context.Background())
	if errors.As(err, &he) {
		t.Fatal("transport failure reported as an HTTP response")
	}
}

func TestInstallCAFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src.pem"), filepath.Join(dir, CAFileName)
	if err := os.WriteFile(src, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallCAFile(src, dst); err == nil {
		t.Fatal("accepted a file without PEM certificates")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("invalid CA was copied: %v", err)
	}
	if err := os.WriteFile(src, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t)}), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 { // re-enrolling with the same CA overwrites the copy
		if err := InstallCAFile(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	if err := InstallCAFile(dst, dst); err != nil {
		t.Fatalf("installing the file onto itself: %v", err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(dst)
	if !bytes.Equal(a, b) {
		t.Fatal("copied CA differs")
	}
}

func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
