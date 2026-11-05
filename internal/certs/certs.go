// Package certs manages plaitd's TLS material: a controller-local CA and
// server certificate when no certificate is supplied, and hot reloading of
// certificate files that are replaced on disk (e.g. by certbot).
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Files in an auto-TLS directory. server.pem holds the leaf followed by the
// CA so clients pinning the CA fingerprint receive it in the handshake.
const (
	CAFile     = "ca.pem"
	caKeyFile  = "ca.key"
	ServerFile = "server.pem"
	ServerKey  = "server.key"
)

const (
	caLifetime     = 20 * 365 * 24 * time.Hour
	serverLifetime = 397 * 24 * time.Hour // within browser limits for user-trusted roots
	renewBefore    = 30 * 24 * time.Hour
)

// Auto is a controller-local CA and the server certificate it issues.
type Auto struct {
	Dir   string
	Names []string // DNS names and IP addresses for the server certificate
	Now   func() time.Time
}

func (a *Auto) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Auto) CertFile() string { return filepath.Join(a.Dir, ServerFile) }
func (a *Auto) KeyFile() string  { return filepath.Join(a.Dir, ServerKey) }

// Ensure creates the CA if it is missing and (re)issues the server
// certificate when it is missing, not issued by the current CA, near expiry,
// or does not cover exactly Names. The CA is never replaced once it exists,
// so its fingerprint stays valid for enrolled gateways. It reports whether
// the server certificate was (re)issued.
func (a *Auto) Ensure() (bool, error) {
	if len(a.Names) == 0 {
		return false, errors.New("no server names for the TLS certificate")
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return false, err
	}
	ca, caKey, err := a.loadOrCreateCA()
	if err != nil {
		return false, err
	}
	if leaf, err := loadLeaf(a.CertFile(), a.KeyFile()); err == nil && a.current(leaf, ca) {
		return false, nil
	}
	return true, a.issue(ca, caKey)
}

func (a *Auto) current(leaf, ca *x509.Certificate) bool {
	if leaf.CheckSignatureFrom(ca) != nil || a.now().Add(renewBefore).After(leaf.NotAfter) {
		return false
	}
	have := leaf.DNSNames
	for _, ip := range leaf.IPAddresses {
		have = append(have, ip.String())
	}
	want := normalize(a.Names)
	return slices.Equal(normalize(have), want)
}

func normalize(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if ip, err := netip.ParseAddr(n); err == nil {
			n = ip.Unmap().String()
		} else {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (a *Auto) loadOrCreateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath, keyPath := filepath.Join(a.Dir, CAFile), filepath.Join(a.Dir, caKeyFile)
	if _, err := os.Stat(certPath); err == nil {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("controller CA: %w", err)
		}
		key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("controller CA key is not ECDSA")
		}
		return pair.Leaf, key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	host, _ := os.Hostname()
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Plait controller CA " + host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	// Key first: a CA certificate without its key is unusable.
	if err := writeKey(keyPath, key); err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(certPath, pemBlock("CERTIFICATE", der), 0o644); err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return ca, key, err
}

func (a *Auto) issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: a.Names[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(serverLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range normalize(a.Names) {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	// Key, then chain: the reloader retries until the pair matches.
	if err := writeKey(a.KeyFile(), key); err != nil {
		return err
	}
	chain := append(pemBlock("CERTIFICATE", der), pemBlock("CERTIFICATE", ca.Raw)...)
	return writeAtomic(a.CertFile(), chain, 0o644)
}

// DefaultNames is the server identity used when none is configured: the
// host name, its FQDN when resolvable, loopback names, and every global or
// private unicast address on the host.
func DefaultNames() []string {
	names := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
		if cname, err := net.LookupCNAME(h); err == nil && cname != "" {
			names = append(names, strings.TrimSuffix(cname, "."))
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			names = append(names, ip.String())
		}
	}
	return normalize(names)
}

// Fingerprint is the pin format agents accept: "sha256:" and the hex SHA-256
// of the certificate's DER encoding.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ReadCA returns the PEM and fingerprint of the CA in an auto-TLS directory.
func ReadCA(dir string) (pemBytes []byte, fingerprint string, err error) {
	pemBytes, err = os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("%s: no certificate", filepath.Join(dir, CAFile))
	}
	return pemBytes, Fingerprint(block.Bytes), nil
}

func loadLeaf(certFile, keyFile string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return pair.Leaf, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeAtomic(path, pemBlock("PRIVATE KEY", der), 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
