package model

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ValidationError marks an error caused by invalid intent rather than an
// internal failure. Callers may show its message to administrators.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// IsValidation reports whether err is (or wraps) a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

// ValidateName checks a human-readable site or device name.
func ValidateName(name string) error {
	if name == "" || len(name) > 64 {
		return invalid("name must be 1-64 characters")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_. ", r)) {
			return invalid("name %q may contain only letters, digits, space, '-', '_', and '.'", name)
		}
	}
	if strings.TrimSpace(name) != name {
		return invalid("name %q has leading or trailing space", name)
	}
	return nil
}

// ValidateInterfaceName checks a Linux interface name. The allowed character
// set is deliberately narrower than the kernel's so names are safe to embed
// in nftables rulesets without quoting.
func ValidateInterfaceName(name string) error {
	if name == "" || len(name) > 15 {
		return invalid("interface name must be 1-15 characters")
	}
	if name == "." || name == ".." {
		return invalid("invalid interface name %q", name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return invalid("interface name %q may contain only letters, digits, '-', '_', and '.'", name)
		}
	}
	return nil
}

// ValidateEndpointHost accepts an IP literal or a DNS hostname. Scoped IPv6
// literals are refused: a zone names an interface on one machine, means
// nothing in a shared profile, and may contain any byte.
func ValidateEndpointHost(host string) error {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return invalid("endpoint host %q must not have an IPv6 zone", host)
		}
		return nil
	}
	return validateHostname(host, "endpoint host")
}

func validateHostname(host, what string) error {
	h := strings.TrimSuffix(host, ".")
	if h == "" || len(h) > 253 {
		return invalid("%s %q is not a valid hostname", what, host)
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid("%s %q is not a valid hostname", what, host)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return invalid("%s %q is not a valid hostname", what, host)
			}
		}
	}
	return nil
}

// ValidateSearchDomains checks an ordered, optional list of DNS search
// domains.
func ValidateSearchDomains(domains []string) error {
	seen := map[string]bool{}
	for _, d := range domains {
		if err := validateHostname(d, "search domain"); err != nil {
			return err
		}
		k := strings.ToLower(d)
		if seen[k] {
			return invalid("duplicate search domain %s", d)
		}
		seen[k] = true
	}
	return nil
}

// ValidateMTU checks a gateway or client MTU.
func ValidateMTU(mtu int) error {
	if mtu < 576 || mtu > 1500 {
		return invalid("MTU %d must be between 576 and 1500", mtu)
	}
	return nil
}

// MaxGatewayTCPPorts bounds the gateway access list; it is meant for a few
// management ports, not general service exposure.
const MaxGatewayTCPPorts = 16

// ParseTCPPorts parses a comma- or space-separated port list into sorted,
// unique ports. An empty string means none.
func ParseTCPPorts(s string) ([]uint16, error) {
	var ports []uint16
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		var n int
		if _, err := fmt.Sscanf(f, "%d", &n); err != nil || fmt.Sprint(n) != f {
			return nil, invalid("TCP port %q is not a number", f)
		}
		if n < 1 || n > 65535 {
			return nil, invalid("TCP port %d must be between 1 and 65535", n)
		}
		ports = append(ports, uint16(n))
	}
	return NormalizeTCPPorts(ports)
}

// NormalizeTCPPorts sorts and validates a port list; duplicates are removed.
func NormalizeTCPPorts(ports []uint16) ([]uint16, error) {
	out := slices.Clone(ports)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > 0 && out[0] == 0 {
		return nil, invalid("TCP port 0 is not valid")
	}
	if len(out) > MaxGatewayTCPPorts {
		return nil, invalid("at most %d gateway TCP ports", MaxGatewayTCPPorts)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// FormatTCPPorts is the canonical stored and displayed form, e.g. "22,2222".
func FormatTCPPorts(ports []uint16) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = fmt.Sprint(p)
	}
	return strings.Join(s, ",")
}

// ValidateKeepalive checks a persistent keepalive interval in seconds.
func ValidateKeepalive(seconds int) error {
	if seconds < 0 || seconds > 65535 {
		return invalid("persistent keepalive %d must be between 0 and 65535", seconds)
	}
	return nil
}

// ParsePrefix parses an IPv4 prefix and requires canonical form.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, invalid("invalid prefix %q", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, invalid("prefix %s is not IPv4; IPv6 is outside v1 scope", p)
	}
	if p != p.Masked() {
		return netip.Prefix{}, invalid("prefix %s is not canonical (use %s)", p, p.Masked())
	}
	return p, nil
}

// ValidateSiteSubnets checks a site's LAN prefixes against the client pool and
// each other, returning them canonical and sorted.
func ValidateSiteSubnets(pool Pool, subnets []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(subnets))
	for _, p := range subnets {
		if !p.IsValid() || !p.Addr().Is4() {
			return nil, invalid("site prefix %s is not IPv4", p)
		}
		p = p.Masked()
		if p.Bits() == 0 {
			return nil, invalid("default route %s cannot be a site prefix; v1 is split-tunnel only", p)
		}
		if p.Overlaps(pool.Prefix) {
			return nil, invalid("site prefix %s intersects client pool %s", p, pool.Prefix)
		}
		out = append(out, p)
	}
	SortPrefixes(out)
	for i := 1; i < len(out); i++ {
		if out[i-1].Overlaps(out[i]) {
			return nil, invalid("site prefixes %s and %s overlap", out[i-1], out[i])
		}
	}
	return out, nil
}

// ValidateDNSServers checks resolver addresses. v1 tunnels are IPv4-only, but
// a resolver reached outside the tunnel may be any address family.
func ValidateDNSServers(servers []netip.Addr) error {
	seen := map[netip.Addr]bool{}
	for _, a := range servers {
		if !a.IsValid() || a.IsUnspecified() {
			return invalid("invalid DNS server %s", a)
		}
		if a.Zone() != "" {
			return invalid("DNS server %q must not have an IPv6 zone", a)
		}
		if seen[a] {
			return invalid("duplicate DNS server %s", a)
		}
		seen[a] = true
	}
	return nil
}

// SortPrefixes orders prefixes by address, then by prefix length.
func SortPrefixes(ps []netip.Prefix) {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
}
