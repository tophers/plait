package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures are real `nft -j list chain` output (nftables 1.0.9) for rulesets
// shaped like a host-managed firewall: input and forward chains with a drop
// policy, wildcard interface rules, port sets and ranges, named sets, and
// jumps.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChainBlockers(t *testing.T) {
	plait := Traffic{Interface: "plait0", Egress: "eth0", ListenPort: 51820}
	for _, tc := range []struct {
		name, hook string
		t          Traffic
		want       []string // substrings, one per expected warning
	}{
		// Host ruleset that already integrates Plait.
		{"host-input", "input", plait, nil},
		{"host-forward", "forward", plait, nil},
		{"host-input", "input", Traffic{"plait0", "eth0", 51111}, []string{"UDP port 51111"}},
		// The same ruleset before Plait: wg* only, and the old WireGuard port.
		{"current-input", "input", plait, []string{"UDP port 51820, so WireGuard handshakes may be dropped; for example: udp dport 51820 accept"}},
		{"current-forward", "forward", plait, []string{`traffic from plait0; for example: iifname "plait*" accept`}},
		// Exact interface name and a port range; no established rule.
		{"legacy-input", "input", plait, nil},
		{"legacy-forward", "forward", plait, []string{"replies to plait0"}},
		// Named sets, negations, and jumps cannot be judged: no warnings.
		{"opaque-input", "input", plait, nil},
		{"opaque-forward", "forward", plait, nil},
	} {
		got, err := chainBlockers(fixture(t, tc.name), tc.hook, tc.t)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s (port %d): got %q, want %d warning(s)", tc.name, tc.t.ListenPort, got, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: warning %q lacks %q", tc.name, got[i], w)
			}
		}
	}
}

func TestOpaqueNegationStillExcludes(t *testing.T) {
	// "udp dport != 51820 drop" ends in drop, so it never counts as an
	// accept; a different port is still not shown as accepted by it.
	got, err := chainBlockers(fixture(t, "opaque-input"), "input", Traffic{"plait0", "eth0", 51111})
	if err != nil || len(got) != 0 {
		t.Fatalf("the jump to another chain may accept: got %q, %v", got, err)
	}
}

func TestIfnameMatches(t *testing.T) {
	for _, tc := range []struct {
		pat, name string
		want      bool
	}{
		{`"plait*"`, "plait0", true},
		{`"plait0"`, "plait0", true},
		{`"wg*"`, "plait0", false},
		{`"*"`, "plait0", true},
		{`"plait\\*"`, "plait0", false}, // escaped: a literal asterisk
	} {
		if got := ifnameMatches([]byte(tc.pat), tc.name); got != tc.want {
			t.Errorf("%s vs %s: %v", tc.pat, tc.name, got)
		}
	}
}
