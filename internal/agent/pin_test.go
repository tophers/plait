package agent

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"plait/internal/certs"
)

// pinnedServer serves a certificate issued by a fresh controller CA for names.
func pinnedServer(t *testing.T, names ...string) (url, caFingerprint, leafFingerprint string, caPEM []byte) {
	t.Helper()
	a := &certs.Auto{Dir: filepath.Join(t.TempDir(), "tls"), Names: names}
	if _, err := a.Ensure(); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(a.CertFile(), a.KeyFile())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caPEM, fp, err := certs.ReadCA(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, fp, certs.Fingerprint(pair.Certificate[0]), caPEM
}

func TestFetchPinnedCA(t *testing.T) {
	ctx := context.Background()
	url, fp, leafFP, caPEM := pinnedServer(t, "127.0.0.1")

	got, err := FetchPinnedCA(ctx, url, strings.ToUpper(fp[:7])+fp[7:])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(caPEM) {
		t.Fatal("returned CA differs from the controller's")
	}
	// The fetched CA then verifies normal connections.
	c := NewClient(url, "")
	dir := t.TempDir()
	if err := InstallCAPEM(got, filepath.Join(dir, CAFileName)); err != nil {
		t.Fatal(err)
	}
	if err := c.UseCAFile(filepath.Join(dir, CAFileName)); err != nil {
		t.Fatal(err)
	}
	if resp, err := c.HTTP.Get(url); err != nil {
		t.Fatalf("request with fetched CA: %v", err)
	} else {
		resp.Body.Close()
	}

	_, otherFP, _, _ := pinnedServer(t, "127.0.0.1")
	for name, pin := range map[string]string{
		"another CA":       otherFP,
		"leaf, not the CA": leafFP,
		"malformed":        "sha256:abc",
		"no prefix":        fp[7:],
	} {
		if _, err := FetchPinnedCA(ctx, url, pin); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := FetchPinnedCA(ctx, strings.Replace(url, "https", "http", 1), fp); err == nil {
		t.Error("plain http accepted")
	}
}

func TestFetchPinnedCARejectsWrongHostName(t *testing.T) {
	url, fp, _, _ := pinnedServer(t, "plait.example.net")
	if _, err := FetchPinnedCA(context.Background(), url, fp); err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("certificate for another name accepted (err=%v)", err)
	}
}
