package model

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseTCPPorts(t *testing.T) {
	for in, want := range map[string][]uint16{
		"":             nil,
		"  ":           nil,
		"22":           {22},
		"2222, 22":     {22, 2222},
		"22,22\n443":   {22, 443},
		"22 8443 2222": {22, 2222, 8443},
	} {
		got, err := ParseTCPPorts(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "65536", "ssh", "22x", "-1", "1.5", "+22"} {
		if _, err := ParseTCPPorts(bad); err == nil || !IsValidation(err) {
			t.Errorf("%q accepted (err %v)", bad, err)
		}
	}
	many := make([]uint16, MaxGatewayTCPPorts+1)
	for i := range many {
		many[i] = uint16(1000 + i)
	}
	if _, err := NormalizeTCPPorts(many); err == nil {
		t.Error("too many ports accepted")
	}
	if got := FormatTCPPorts([]uint16{22, 2222}); got != "22,2222" {
		t.Errorf("FormatTCPPorts = %q", got)
	}
}

func TestScopedAddressesRejected(t *testing.T) {
	scoped := netip.MustParseAddr("fe80::1%eth0\nPreUp = id")
	if err := ValidateDNSServers([]netip.Addr{scoped}); err == nil || !IsValidation(err) {
		t.Errorf("scoped DNS server accepted (err %v)", err)
	}
	if err := ValidateDNSServers([]netip.Addr{netip.MustParseAddr("fe80::1")}); err != nil {
		t.Errorf("unscoped link-local DNS server rejected: %v", err)
	}
	for _, bad := range []string{"fe80::1%eth0", "fe80::1%eth0\nPostUp = id"} {
		if err := ValidateEndpointHost(bad); err == nil || !IsValidation(err) {
			t.Errorf("endpoint host %q accepted (err %v)", bad, err)
		}
	}
	for _, ok := range []string{"203.0.113.1", "2001:db8::1", "vpn.example.com"} {
		if err := ValidateEndpointHost(ok); err != nil {
			t.Errorf("endpoint host %q rejected: %v", ok, err)
		}
	}
}
