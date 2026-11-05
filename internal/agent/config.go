// Package agent implements plait-agent: durable desired-state caching,
// validation, reconciliation of Linux resources, and controller polling.
package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const DefaultConfigPath = "/etc/plait/agent.json"

type Config struct {
	SiteID         string `json:"site_id,omitempty"`
	ControllerURL  string `json:"controller_url,omitempty"`
	CredentialFile string `json:"credential_file"`
	StateDir       string `json:"state_dir"`
	NftPath        string `json:"nft_path"`
	// CAFile optionally names a PEM bundle used instead of the system roots
	// to verify the controller certificate. Verification is never disabled.
	CAFile string `json:"ca_file,omitempty"`
	// NftIncludeFile, when set, receives a copy of Plait's nftables table
	// whenever it changes, for a host ruleset that flushes everything on
	// reload to include (e.g. /etc/nftables/conf.d/plait.nft). The agent
	// still applies the table itself.
	NftIncludeFile string `json:"nft_include_file,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{
		CredentialFile: "/var/lib/plait/agent.credential",
		StateDir:       "/var/lib/plait",
		NftPath:        "/usr/sbin/nft",
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !filepath.IsAbs(c.NftPath) || !filepath.IsAbs(c.StateDir) {
		return nil, fmt.Errorf("%s: nft_path and state_dir must be absolute", path)
	}
	if err := CheckNftIncludeFile(c.NftIncludeFile); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.ControllerURL != "" {
		if err := checkControllerURL(c.ControllerURL); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return c, nil
}

// Save writes the configuration back atomically, e.g. after enrollment.
func (c *Config) Save(path string) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'))
}

// CheckNftIncludeFile accepts "" (disabled) or an absolute *.nft path.
func CheckNftIncludeFile(p string) error {
	if p != "" && (!filepath.IsAbs(p) || filepath.Ext(p) != ".nft" || filepath.Clean(p) != p) {
		return fmt.Errorf("nft_include_file %q must be an absolute path ending in .nft", p)
	}
	return nil
}

// CAFileName is where enrollment keeps the controller CA, beside the agent
// configuration: the service cannot read home directories (ProtectHome).
const CAFileName = "controller-ca.pem"

// InstallCAFile copies PEM roots from src to dst after checking that they
// parse, so the configuration never names an unreadable or invalid file.
func InstallCAFile(src, dst string) error {
	pem, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s contains no PEM certificates", src)
	}
	if filepath.Clean(src) == filepath.Clean(dst) {
		return nil
	}
	return writeAtomic(dst, pem)
}

// InstallCAPEM stores PEM roots obtained some other way (FetchPinnedCA).
func InstallCAPEM(pem []byte, dst string) error {
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return fmt.Errorf("no PEM certificates to install")
	}
	return writeAtomic(dst, pem)
}

// WriteCredential stores a site credential with mode 0600.
func WriteCredential(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeAtomic(path, []byte(token+"\n"))
}

// checkControllerURL requires HTTPS, allowing plain HTTP only to loopback
// for local testing.
func checkControllerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid controller_url %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("controller_url must use https")
}

// ReadCredential reads the site bearer credential, refusing loose permissions.
func ReadCredential(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("credential file %s must not be accessible by group or others", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("credential file %s is empty", path)
	}
	return tok, nil
}
