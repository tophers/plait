package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTLSMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Controller
		want TLSMode
	}{
		{"files", Controller{Listen: "0.0.0.0:8443", TLSCertFile: "c", TLSKeyFile: "k"}, TLSFiles},
		{"public listener without files is auto", Controller{Listen: "0.0.0.0:8443"}, TLSAuto},
		{"auto with names", Controller{Listen: "[::]:8443", TLSNames: []string{"plait.example.net"}}, TLSAuto},
		{"loopback is plaintext for a proxy", Controller{Listen: "127.0.0.1:8443"}, TLSOff},
		{"localhost", Controller{Listen: "localhost:8443"}, TLSOff},
		{"ipv6 loopback", Controller{Listen: "[::1]:8443"}, TLSOff},
	} {
		if got, err := tc.c.TLSMode(); err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	for name, c := range map[string]Controller{
		"cert without key":   {Listen: "0.0.0.0:8443", TLSCertFile: "c"},
		"names with files":   {Listen: "0.0.0.0:8443", TLSCertFile: "c", TLSKeyFile: "k", TLSNames: []string{"x"}},
		"names on loopback":  {Listen: "127.0.0.1:8443", TLSNames: []string{"x"}},
		"unparseable listen": {Listen: "8443"},
	} {
		if _, err := c.TLSMode(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plaitd.json")
	os.WriteFile(path, []byte(`{"client_pool":"10.99.0.0/24","listen":"0.0.0.0:8443","pool_exclusions":["10.99.0.8"]}`), 0o600)
	c, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSNames = []string{"plait.example.net"}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	got, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientPool != "10.99.0.0/24" || len(got.PoolExclusions) != 1 || got.TLSNames[0] != "plait.example.net" || got.Database != c.Database {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if c.AutoTLSDir() != "/var/lib/plaitd/tls" {
		t.Fatalf("AutoTLSDir = %s", c.AutoTLSDir())
	}
}
