package model

import (
	"errors"
	"net/netip"
	"testing"
)

func TestPoolAllocation(t *testing.T) {
	pool, err := ParsePool("10.0.0.0/29", []string{"10.0.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	used := map[netip.Addr]bool{}
	var got []string
	for {
		a, err := pool.LowestFree(used)
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		used[a] = true
		got = append(got, a.String())
	}
	// .0 network, .1 reserved, .3 excluded, .7 broadcast.
	want := []string{"10.0.0.2", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	if len(got) != len(want) {
		t.Fatalf("allocated %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allocated %v, want %v", got, want)
		}
	}
}

func TestParsePoolRejects(t *testing.T) {
	cases := []struct {
		prefix string
		excl   []string
	}{
		{"10.0.0.1/24", nil},                  // not canonical
		{"10.0.0.0/30", nil},                  // too small
		{"fd00::/64", nil},                    // IPv6
		{"10.0.0.0/24", []string{"10.0.1.5"}}, // exclusion outside pool
	}
	for _, c := range cases {
		if _, err := ParsePool(c.prefix, c.excl); err == nil {
			t.Errorf("ParsePool(%s, %v) succeeded", c.prefix, c.excl)
		}
	}
}

func TestValidateSiteSubnets(t *testing.T) {
	pool, _ := ParsePool("10.0.0.0/24", nil)
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	bad := [][]netip.Prefix{
		{p("0.0.0.0/0")},
		{p("10.0.0.0/16")},                         // contains pool
		{p("10.0.0.128/25")},                       // inside pool
		{p("192.168.0.0/16"), p("192.168.1.0/24")}, // nested
		{p("10.15.0.0/24"), p("10.15.0.0/24")},     // duplicate
	}
	for _, b := range bad {
		if _, err := ValidateSiteSubnets(pool, b); err == nil || !IsValidation(err) {
			t.Errorf("ValidateSiteSubnets(%v) = %v, want validation error", b, err)
		}
	}
	out, err := ValidateSiteSubnets(pool, []netip.Prefix{p("10.15.0.0/24"), p("10.13.37.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != p("10.13.37.0/24") {
		t.Fatalf("not sorted: %v", out)
	}
}

func TestValidateInterfaceName(t *testing.T) {
	for _, ok := range []string{"enp1s0", "eth0.100", "br-lan"} {
		if err := ValidateInterfaceName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a-very-long-interface", "eth0;drop", `eth"0`, "eth 0", ".."} {
		if err := ValidateInterfaceName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
