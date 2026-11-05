// Package firewall renders and inspects Plait's dedicated nftables table.
//
// The ruleset is replaced atomically in one `nft -f -` transaction. Drift is
// detected from `nft -j` JSON: chain hooks and policies, set elements, and
// the ordered list of rule comments in each chain. Rule bodies are not
// compared, so an edit that keeps a rule's comment is not detected.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"plait/internal/model"
)

const Table = "plait"

// Policy is the complete desired firewall state for one gateway.
type Policy struct {
	Interface   string // plait0
	Egress      string // LAN egress interface
	ListenPort  uint16
	MTU         int // plait0 MTU, used to derive the MSS clamp
	Clients     []netip.Addr
	LANPrefixes []netip.Prefix
	// GatewayTCPPorts on this host that clients may reach; all other traffic
	// from the tunnel to the gateway itself is dropped.
	GatewayTCPPorts []uint16
}

// MSS is the TCP MSS clamp derived from the tunnel MTU: IPv4 (20) and TCP
// (20) headers without options. Smaller advertised values are preserved.
func (p Policy) MSS() int { return p.MTU - 40 }

func (p Policy) Validate() error {
	if err := model.ValidateInterfaceName(p.Interface); err != nil {
		return err
	}
	if err := model.ValidateInterfaceName(p.Egress); err != nil {
		return err
	}
	if p.Interface == p.Egress {
		return fmt.Errorf("egress interface must differ from %s", p.Interface)
	}
	if p.ListenPort == 0 {
		return fmt.Errorf("listen port is required")
	}
	if err := model.ValidateMTU(p.MTU); err != nil {
		return err
	}
	for _, a := range p.Clients {
		if !a.Is4() {
			return fmt.Errorf("client address %s is not IPv4", a)
		}
	}
	for _, l := range p.LANPrefixes {
		if !l.Addr().Is4() || l != l.Masked() || l.Bits() == 0 {
			return fmt.Errorf("invalid LAN prefix %s", l)
		}
	}
	if ports, err := model.NormalizeTCPPorts(p.GatewayTCPPorts); err != nil || len(ports) != len(p.GatewayTCPPorts) {
		return fmt.Errorf("invalid gateway TCP ports %v", p.GatewayTCPPorts)
	}
	return nil
}

// rule is one ruleset line plus the comment that identifies it.
type rule struct {
	chain, id, body string
}

func (p Policy) rules() []rule {
	in, eg := quote(p.Interface), quote(p.Egress)
	authorized := fmt.Sprintf("iifname %s oifname %s ip saddr @clients ip daddr @lans", in, eg)
	reply := fmt.Sprintf("iifname %s oifname %s ip saddr @lans ip daddr @clients", eg, in)
	mss := fmt.Sprintf("tcp flags syn / syn,rst tcp option maxseg size > %d tcp option maxseg size set %d", p.MSS(), p.MSS())
	rules := []rule{
		{"input", "wg-listen", fmt.Sprintf("udp dport %d accept", p.ListenPort)},
	}
	if len(p.GatewayTCPPorts) > 0 {
		ports := model.FormatTCPPorts(p.GatewayTCPPorts)
		rules = append(rules, rule{"input", "gateway-access",
			fmt.Sprintf("iifname %s ip saddr @clients tcp dport { %s } accept", in, strings.ReplaceAll(ports, ",", ", "))})
	}
	return append(rules, []rule{
		{"input", "deny-tunnel-local", fmt.Sprintf("iifname %s drop", in)},
		// MSS clamps come before any terminating accept; they match SYN in the
		// client-to-LAN direction and SYN-ACK in the reply direction.
		{"forward", "mss-out", authorized + " " + mss},
		{"forward", "mss-in", reply + " " + mss},
		{"forward", "client-to-lan", authorized + " accept"},
		{"forward", "return", fmt.Sprintf("iifname %s oifname %s ip daddr @clients ct state established,related accept", eg, in)},
		{"forward", "deny-from-tunnel", fmt.Sprintf("iifname %s drop", in)},
		{"forward", "deny-to-tunnel", fmt.Sprintf("oifname %s drop", in)},
		{"postrouting", "masquerade", fmt.Sprintf("oifname %s ip saddr @clients ip daddr @lans masquerade", eg)},
	}...)
}

type chainSpec struct {
	name, typ, hook, priority string
}

var chains = []chainSpec{
	{"input", "filter", "input", "filter"},
	{"forward", "filter", "forward", "filter"},
	{"postrouting", "nat", "postrouting", "srcnat"},
}

func quote(s string) string { return `"` + s + `"` }

// ruleComment identifies a rule and fingerprints its body. Drift compares
// comments rather than the rule expressions nft reports back (which it
// normalizes), so any change to a body (an interface, port, or MSS) must
// change the comment.
func ruleComment(r rule) string {
	sum := sha256.Sum256([]byte(r.body))
	return "plait:" + r.chain + ":" + r.id + ":" + hex.EncodeToString(sum[:6])
}

// Render returns an nft script that atomically replaces the plait table. The
// leading empty table declaration makes the delete succeed on first install.
func Render(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	clients := slices.Clone(p.Clients)
	slices.SortFunc(clients, netip.Addr.Compare)
	lans := slices.Clone(p.LANPrefixes)
	model.SortPrefixes(lans)

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)

	b.WriteString("\tset clients {\n\t\ttype ipv4_addr\n")
	if len(clients) > 0 {
		s := make([]string, len(clients))
		for i, a := range clients {
			s[i] = a.String()
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(s, ", "))
	}
	b.WriteString("\t}\n")

	b.WriteString("\tset lans {\n\t\ttype ipv4_addr\n\t\tflags interval\n")
	if len(lans) > 0 {
		s := make([]string, len(lans))
		for i, l := range lans {
			s[i] = l.String()
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(s, ", "))
	}
	b.WriteString("\t}\n")

	rules := p.rules()
	for _, c := range chains {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype %s hook %s priority %s; policy accept;\n", c.name, c.typ, c.hook, c.priority)
		for _, r := range rules {
			if r.chain == c.name {
				fmt.Fprintf(&b, "\t\t%s comment %s\n", r.body, quote(ruleComment(r)))
			}
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// Observed is the inspected state of the plait table.
type Observed struct {
	Chains   map[string]ObservedChain
	Clients  []netip.Addr
	LANs     []netip.Prefix
	Comments map[string][]string // chain -> ordered rule comments
}

type ObservedChain struct {
	Type, Hook, Policy string
	Priority           int
}

var priorities = map[string]int{"filter": 0, "srcnat": 100}

// Drift describes how observed state differs from a policy; empty means none.
func Drift(p Policy, o *Observed) []string {
	if o == nil {
		return []string{"table inet plait is missing"}
	}
	var d []string
	for _, c := range chains {
		oc, ok := o.Chains[c.name]
		if !ok {
			d = append(d, "chain "+c.name+" is missing")
			continue
		}
		if oc.Type != c.typ || oc.Hook != c.hook || oc.Policy != "accept" || oc.Priority != priorities[c.priority] {
			d = append(d, "chain "+c.name+" has unexpected type, hook, priority, or policy")
		}
	}
	if len(o.Chains) != len(chains) {
		d = append(d, "table has unexpected chains")
	}
	want := map[string][]string{}
	for _, r := range p.rules() {
		want[r.chain] = append(want[r.chain], ruleComment(r))
	}
	for _, c := range chains {
		if !slices.Equal(want[c.name], o.Comments[c.name]) {
			d = append(d, "chain "+c.name+" rules differ")
		}
	}
	clients := slices.Clone(p.Clients)
	slices.SortFunc(clients, netip.Addr.Compare)
	got := slices.Clone(o.Clients)
	slices.SortFunc(got, netip.Addr.Compare)
	if !slices.Equal(clients, got) {
		d = append(d, "set clients differs")
	}
	lans := slices.Clone(p.LANPrefixes)
	model.SortPrefixes(lans)
	gotLANs := slices.Clone(o.LANs)
	model.SortPrefixes(gotLANs)
	if !slices.Equal(lans, gotLANs) {
		d = append(d, "set lans differs")
	}
	return d
}
