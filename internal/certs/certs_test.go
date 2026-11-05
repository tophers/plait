package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return out
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

func TestAutoIssuesVerifiableChainAndKeepsCA(t *testing.T) {
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	a := &Auto{Dir: filepath.Join(t.TempDir(), "tls"), Names: []string{"plait.example.net", "192.0.2.10", "localhost"}, Now: func() time.Time { return now }}
	changed, err := a.Ensure()
	if err != nil || !changed {
		t.Fatalf("first Ensure: changed=%v err=%v", changed, err)
	}
	for f, mode := range map[string]os.FileMode{CAFile: 0o644, caKeyFile: 0o600, ServerFile: 0o644, ServerKey: 0o600} {
		fi, err := os.Stat(filepath.Join(a.Dir, f))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v, err %v; want %o", f, fi.Mode().Perm(), err, mode)
		}
	}
	chain := readChain(t, a.CertFile())
	if len(chain) != 2 || !chain[1].IsCA {
		t.Fatalf("server.pem must hold leaf then CA, got %d certs", len(chain))
	}
	caPEM, fp, err := ReadCA(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if fp != Fingerprint(chain[1].Raw) {
		t.Fatal("fingerprint does not match the CA sent in the chain")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	for _, name := range []string{"plait.example.net", "192.0.2.10", "localhost"} {
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: now}); err != nil {
			t.Fatalf("verify as %s: %v", name, err)
		}
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.example.net", CurrentTime: now}); err == nil {
		t.Fatal("certificate verified for a name it does not cover")
	}

	// Idempotent; name order and case do not matter.
	a.Names = []string{"LOCALHOST", "192.0.2.10", "plait.example.net."}
	if changed, err := a.Ensure(); err != nil || changed {
		t.Fatalf("second Ensure reissued: changed=%v err=%v", changed, err)
	}

	// A new name reissues the leaf under the same CA.
	a.Names = append(a.Names, "plait.internal")
	if changed, err := a.Ensure(); err != nil || !changed {
		t.Fatalf("name change: changed=%v err=%v", changed, err)
	}
	if _, fp2, _ := ReadCA(a.Dir); fp2 != fp {
		t.Fatal("CA changed when the server certificate was reissued")
	}

	// Near expiry renews.
	leaf := readChain(t, a.CertFile())[0]
	now = leaf.NotAfter.Add(-renewBefore + time.Hour)
	if changed, err := a.Ensure(); err != nil || !changed {
		t.Fatalf("near expiry: changed=%v err=%v", changed, err)
	}
	if renewed := readChain(t, a.CertFile())[0]; !renewed.NotAfter.After(leaf.NotAfter) {
		t.Fatal("renewed certificate does not extend validity")
	}
}

func TestAutoRequiresNames(t *testing.T) {
	if _, err := (&Auto{Dir: t.TempDir()}).Ensure(); err == nil {
		t.Fatal("Ensure without names succeeded")
	}
}

func TestDefaultNamesIncludeLoopback(t *testing.T) {
	names := DefaultNames()
	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Fatalf("DefaultNames() = %v, missing %s", names, want)
		}
	}
}

func TestReloaderPicksUpReplacementAndSurvivesBadPair(t *testing.T) {
	dir := t.TempDir()
	a := &Auto{Dir: dir, Names: []string{"one.example.net"}}
	if _, err := a.Ensure(); err != nil {
		t.Fatal(err)
	}
	var errs int
	r := &Reloader{CertFile: a.CertFile(), KeyFile: a.KeyFile(), Interval: time.Nanosecond, OnError: func(error) { errs++ }}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	cn := func() string {
		t.Helper()
		c, err := r.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.Subject.CommonName
	}
	if got := cn(); got != "one.example.net" {
		t.Fatalf("serving %s", got)
	}

	// A mismatched pair (new certificate, old key) keeps the old one.
	other := &Auto{Dir: t.TempDir(), Names: []string{"two.example.net"}}
	if _, err := other.Ensure(); err != nil {
		t.Fatal(err)
	}
	newCert, _ := os.ReadFile(other.CertFile())
	newKey, _ := os.ReadFile(other.KeyFile())
	future := time.Now().Add(time.Minute)
	os.WriteFile(a.CertFile(), newCert, 0o644)
	os.Chtimes(a.CertFile(), future, future)
	if got := cn(); got != "one.example.net" || errs == 0 {
		t.Fatalf("after half-replaced pair: serving %s, errors %d", got, errs)
	}

	// Completing the replacement switches without a restart.
	os.WriteFile(a.KeyFile(), newKey, 0o600)
	os.Chtimes(a.KeyFile(), future, future)
	if got := cn(); got != "two.example.net" {
		t.Fatalf("after replacement: serving %s", got)
	}
}
