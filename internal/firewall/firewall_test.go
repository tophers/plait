package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func policy() Policy {
	return Policy{
		Interface: "plait0", Egress: "enp1s0", ListenPort: 51111, MTU: 1420,
		Clients:     []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.4")},
		LANPrefixes: []netip.Prefix{netip.MustParsePrefix("10.15.0.0/24")},
	}
}

func TestRender(t *testing.T) {
	out, err := Render(policy())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet plait {}\ndelete table inet plait\ntable inet plait {",
		"elements = { 10.0.0.4, 10.0.0.5 }",
		"tcp option maxseg size > 1380 tcp option maxseg size set 1380",
		`oifname "enp1s0" ip saddr @clients ip daddr @lans masquerade`,
		"type nat hook postrouting priority srcnat; policy accept;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
	}
	// MSS clamps must precede the terminating accept in forward.
	if strings.Index(out, "plait:forward:mss-in") > strings.Index(out, "plait:forward:client-to-lan") {
		t.Error("MSS clamp after accept")
	}
	if strings.Count(out, " masquerade comment") != 1 {
		t.Error("want exactly one scoped masquerade rule")
	}
}

func TestRenderEmptySetsAndValidation(t *testing.T) {
	p := policy()
	p.Clients = nil
	out, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "elements") != 1 {
		t.Fatalf("empty clients set should have no elements line:\n%s", out)
	}
	for _, bad := range []func(*Policy){
		func(p *Policy) { p.Egress = `eth0" ; flush ruleset ; "` },
		func(p *Policy) { p.Egress = p.Interface },
		func(p *Policy) { p.MTU = 100 },
		func(p *Policy) { p.LANPrefixes = []netip.Prefix{netip.MustParsePrefix("10.15.0.1/24")} },
	} {
		p := policy()
		bad(&p)
		if _, err := Render(p); err == nil {
			t.Errorf("invalid policy rendered: %+v", p)
		}
	}
}

// Representative `nft -j list table inet plait` output.
const sampleJSON = `{"nftables": [
 {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
 {"table": {"family": "inet", "name": "plait", "handle": 7}},
 {"set": {"family": "inet", "name": "clients", "table": "plait", "type": "ipv4_addr", "handle": 1, "elem": ["10.0.0.4", "10.0.0.5"]}},
 {"set": {"family": "inet", "name": "lans", "table": "plait", "type": "ipv4_addr", "handle": 2, "flags": ["interval"], "elem": [{"prefix": {"addr": "10.15.0.0", "len": 24}}]}},
 {"chain": {"family": "inet", "table": "plait", "name": "input", "handle": 3, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
 {"chain": {"family": "inet", "table": "plait", "name": "forward", "handle": 4, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
 {"chain": {"family": "inet", "table": "plait", "name": "postrouting", "handle": 5, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
 {"rule": {"family": "inet", "table": "plait", "chain": "input", "handle": 8, "comment": "plait:input:wg-listen", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "input", "handle": 9, "comment": "plait:input:deny-tunnel-local", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 10, "comment": "plait:forward:mss-out", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 11, "comment": "plait:forward:mss-in", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 12, "comment": "plait:forward:client-to-lan", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 13, "comment": "plait:forward:return", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 14, "comment": "plait:forward:deny-from-tunnel", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "forward", "handle": 15, "comment": "plait:forward:deny-to-tunnel", "expr": []}},
 {"rule": {"family": "inet", "table": "plait", "chain": "postrouting", "handle": 16, "comment": "plait:postrouting:masquerade", "expr": []}}
]}`

// observed parses sampleJSON with each plait:<chain>:<id> comment completed
// with the fingerprint p's rule would carry.
func observed(t *testing.T, p Policy) *Observed {
	t.Helper()
	js := sampleJSON
	for _, r := range p.rules() {
		js = strings.ReplaceAll(js, `"plait:`+r.chain+":"+r.id+`"`, `"`+ruleComment(r)+`"`)
	}
	o, err := ParseObserved([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestParseAndDrift(t *testing.T) {
	o, err := ParseObserved([]byte(sampleJSON))
	if err != nil {
		t.Fatal(err)
	}
	if o.Comments["input"][0] != "plait:input:wg-listen" || len(o.Comments["forward"]) != 6 {
		t.Fatalf("comments = %v", o.Comments)
	}
	o = observed(t, policy())
	if err != nil {
		t.Fatal(err)
	}
	if d := Drift(policy(), o); len(d) != 0 {
		t.Fatalf("unexpected drift: %v", d)
	}
	p := policy()
	p.Clients = p.Clients[:1]
	if d := Drift(p, o); len(d) != 1 || !strings.Contains(d[0], "clients") {
		t.Fatalf("drift = %v", d)
	}
	o.Comments["forward"] = append(o.Comments["forward"], "") // foreign rule inserted
	if d := Drift(policy(), o); len(d) == 0 {
		t.Fatal("inserted rule not detected")
	}
	if d := Drift(policy(), nil); len(d) != 1 {
		t.Fatal("missing table not detected")
	}
}

func TestDriftDetectsRuleBodyChanges(t *testing.T) {
	o := observed(t, policy())
	for name, change := range map[string]func(*Policy){
		"egress":      func(p *Policy) { p.Egress = "enp2s0" },
		"listen port": func(p *Policy) { p.ListenPort = 51112 },
		"mtu":         func(p *Policy) { p.MTU = 1280 },
	} {
		p := policy()
		change(&p)
		if d := Drift(p, o); len(d) == 0 {
			t.Errorf("%s change not detected as drift", name)
		}
	}
}

func TestGatewayAccessRule(t *testing.T) {
	p := policy()
	if out, _ := Render(p); strings.Contains(out, "gateway-access") {
		t.Fatal("gateway access rendered without ports")
	}
	p.GatewayTCPPorts = []uint16{22, 2222}
	out, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `iifname "plait0" ip saddr @clients tcp dport { 22, 2222 } accept comment "plait:input:gateway-access:`
	if !strings.Contains(out, want) {
		t.Fatalf("missing %q:\n%s", want, out)
	}
	if strings.Index(out, "gateway-access") > strings.Index(out, "deny-tunnel-local") {
		t.Fatal("gateway access must precede the tunnel-local drop")
	}

	// Drift compares comments, so a changed port list must change one.
	o := observed(t, p)
	var input []string
	for _, r := range p.rules() {
		if r.chain == "input" {
			input = append(input, ruleComment(r))
		}
	}
	o.Comments["input"] = input
	if d := Drift(p, o); len(d) != 0 {
		t.Fatalf("unexpected drift: %v", d)
	}
	p.GatewayTCPPorts = []uint16{22}
	if d := Drift(p, o); len(d) == 0 {
		t.Fatal("changed gateway ports not detected as drift")
	}
	p.GatewayTCPPorts = []uint16{22, 22}
	if _, err := Render(p); err == nil {
		t.Fatal("duplicate ports accepted")
	}
}
