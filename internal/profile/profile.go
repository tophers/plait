// Package profile assembles a complete WireGuard client configuration from
// controller-supplied material and a locally held private key. It runs only
// where the private key lives (plaitctl, or the equivalent browser code).
package profile

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"plait/internal/protocol"
	"plait/internal/wg"
)

var (
	ErrKeyMismatch = errors.New("private key does not match the registered device public key")
	ErrUnsafeValue = errors.New("profile material contains a control character")
)

type Options struct {
	// Minify omits comments, blank lines, optional whitespace, and fields
	// whose omission preserves semantics (a disabled keepalive), for QR codes.
	Minify bool
}

// Render produces a wg-quick compatible configuration.
func Render(m *protocol.ProfileMaterial, privateKey wg.Key, opts Options) (string, error) {
	if m.SchemaVersion != protocol.ProfileSchemaVersion {
		return "", fmt.Errorf("unsupported profile schema version %d", m.SchemaVersion)
	}
	pub, err := privateKey.PublicKey()
	if err != nil {
		return "", err
	}
	if !pub.Equal(m.PublicKey) {
		return "", ErrKeyMismatch
	}

	var b strings.Builder
	var bad []string
	// line writes one line of the configuration. wg-quick runs some keys
	// (PostUp and friends) as shell commands, so a value that could start a
	// new line must never be written; the controller validates these fields,
	// and this check holds even if a stored value or an older controller
	// does not.
	line := func(s string) {
		if strings.ContainsFunc(s, unsafeRune) {
			bad = append(bad, s)
		}
		b.WriteString(s + "\n")
	}
	sep, listSep := " = ", ", "
	if opts.Minify {
		sep, listSep = "=", ","
	}
	field := func(k, v string) { line(k + sep + v) }

	if !opts.Minify {
		line(fmt.Sprintf("# Plait profile for %s, revision %d", m.DeviceName, m.Revision))
	}
	line("[Interface]")
	field("PrivateKey", privateKey.String())
	field("Address", m.Address.String())
	if dns := dnsLine(m, listSep); dns != "" {
		field("DNS", dns)
	}
	if m.MTU > 0 {
		field("MTU", strconv.Itoa(m.MTU))
	}
	for _, p := range m.Peers {
		if !opts.Minify {
			line("")
			line("# Site: " + p.SiteName)
		}
		line("[Peer]")
		field("PublicKey", p.PublicKey.String())
		field("PresharedKey", p.PresharedKey.String())
		field("Endpoint", p.Endpoint)
		if len(p.AllowedIPs) > 0 {
			field("AllowedIPs", joinPrefixes(p.AllowedIPs, listSep))
		}
		if p.PersistentKeepalive > 0 || !opts.Minify {
			field("PersistentKeepalive", strconv.Itoa(p.PersistentKeepalive))
		}
	}
	if len(bad) > 0 {
		return "", fmt.Errorf("%w: %q", ErrUnsafeValue, bad[0])
	}
	return b.String(), nil
}

// unsafeRune reports control characters (including CR and LF) and the
// Unicode line and paragraph separators.
func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029
}

// dnsLine follows wg-quick: resolver addresses and search domains share the
// DNS key, with non-address entries treated as search domains.
func dnsLine(m *protocol.ProfileMaterial, listSep string) string {
	var parts []string
	for _, a := range m.DNSServers {
		parts = append(parts, a.String())
	}
	if len(parts) > 0 {
		parts = append(parts, m.SearchDomains...)
	}
	return strings.Join(parts, listSep)
}

func joinPrefixes(ps []netip.Prefix, listSep string) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, listSep)
}
