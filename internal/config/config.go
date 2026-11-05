// Package config loads the controller configuration shared by plaitd and
// plaitctl's local administration commands.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"plait/internal/model"
)

const DefaultPath = "/etc/plait/plaitd.json"

type Controller struct {
	Database          string   `json:"database"`
	EncryptionKeyFile string   `json:"encryption_key_file"`
	ClientPool        string   `json:"client_pool"`
	PoolExclusions    []string `json:"pool_exclusions,omitempty"`
	Listen            string   `json:"listen"`
	// TLS: with tls_cert_file and tls_key_file, plaitd serves those files
	// and reloads them when they change. Without them, a loopback listener
	// serves plaintext for a TLS-terminating reverse proxy, and any other
	// listener gets a controller-local CA and certificate, generated and
	// renewed automatically, covering the host's names and addresses plus
	// tls_names (e.g. a public DNS name behind NAT).
	TLSCertFile string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string   `json:"tls_key_file,omitempty"`
	TLSNames    []string `json:"tls_names,omitempty"`
}

type TLSMode string

const (
	TLSFiles TLSMode = "files"
	TLSAuto  TLSMode = "auto"
	TLSOff   TLSMode = "off" // loopback only, behind a proxy
)

// TLSMode reports how plaitd serves TLS for this configuration.
func (c *Controller) TLSMode() (TLSMode, error) {
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return "", fmt.Errorf("tls_cert_file and tls_key_file must be set together")
	}
	if c.TLSCertFile != "" {
		if len(c.TLSNames) > 0 {
			return "", fmt.Errorf("tls_names applies only to the generated certificate; remove it or the certificate files")
		}
		return TLSFiles, nil
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return "", fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() || host == "localhost" {
		if len(c.TLSNames) > 0 {
			return "", fmt.Errorf("listen %s is loopback (plaintext behind a proxy); tls_names has no effect", c.Listen)
		}
		return TLSOff, nil
	}
	return TLSAuto, nil
}

// AutoTLSDir holds the generated CA and certificate, beside the database so
// it is in plaitd's writable state directory.
func (c *Controller) AutoTLSDir() string {
	return filepath.Join(filepath.Dir(c.Database), "tls")
}

// Save writes the configuration atomically with mode 0644 (it holds paths,
// not secrets).
func (c *Controller) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Load(path string) (*Controller, model.Pool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, model.Pool{}, err
	}
	c := &Controller{
		Database:          "/var/lib/plaitd/plaitd.db",
		EncryptionKeyFile: "/etc/plait/psk.key",
		Listen:            "127.0.0.1:8443",
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, model.Pool{}, fmt.Errorf("%s: %w", path, err)
	}
	if c.ClientPool == "" {
		return nil, model.Pool{}, fmt.Errorf("%s: client_pool is required", path)
	}
	if _, err := c.TLSMode(); err != nil {
		return nil, model.Pool{}, fmt.Errorf("%s: %w", path, err)
	}
	pool, err := model.ParsePool(c.ClientPool, c.PoolExclusions)
	if err != nil {
		return nil, model.Pool{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, pool, nil
}
