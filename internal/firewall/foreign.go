package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Traffic describes Plait's packets for checking other tables' policies.
type Traffic struct {
	Interface  string // plait0
	Egress     string // LAN interface
	ListenPort uint16 // WireGuard UDP port
}

// ForeignBlockers inspects base chains outside the plait table that hook
// input or forward with a drop policy. nftables drops a packet if any base
// chain drops it, so Plait's own accepts cannot override these. For each
// such chain it reports, with a suggested rule, Plait traffic that no rule
// clearly accepts. The analysis is deliberately conservative in what it
// reports: rules it cannot evaluate (jumps, address or mark matches) are
// assumed to accept, so a warning means a likely problem, never a proof.
func (n *Nft) ForeignBlockers(ctx context.Context, t Traffic) ([]string, error) {
	out, err := n.run(ctx, "", "-j", "list", "chains")
	if err != nil {
		return nil, err
	}
	var doc nftDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft chains: %w", err)
	}
	var found []string
	for _, item := range doc.Nftables {
		c := item.Chain
		if c == nil || (c.Family == "inet" && c.Table == Table) || c.Policy != "drop" {
			continue
		}
		if c.Hook != "input" && c.Hook != "forward" {
			continue
		}
		if c.Family != "inet" && c.Family != "ip" {
			continue // Plait is IPv4; ip6, arp, bridge, and netdev chains do not see its packets here
		}
		rules, err := n.run(ctx, "", "-j", "list", "chain", c.Family, c.Table, c.Name)
		if err != nil {
			return nil, err
		}
		msgs, err := chainBlockers(rules, c.Hook, t)
		if err != nil {
			return nil, err
		}
		where := fmt.Sprintf("%s chain %s %s %s drops by default and", c.Hook, c.Family, c.Table, c.Name)
		for _, m := range msgs {
			found = append(found, where+" "+m)
		}
	}
	return found, nil
}

// flow is one direction of Plait traffic as other rules see it.
type flow struct {
	iif, oif string
	udpPort  uint16 // 0: any protocol
	ctState  string // "new" or "established"
}

// chainBlockers returns, for a chain's `nft -j list chain` output, the
// Plait flows that no rule in it clearly accepts.
func chainBlockers(listing []byte, hook string, t Traffic) ([]string, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("parse nft chain: %w", err)
	}
	type check struct {
		f       flow
		message string
	}
	var checks []check
	if hook == "input" {
		checks = []check{{flow{iif: t.Egress, udpPort: t.ListenPort, ctState: "new"},
			fmt.Sprintf("no rule clearly accepts UDP port %d, so WireGuard handshakes may be dropped; for example: udp dport %d accept", t.ListenPort, t.ListenPort)}}
	} else {
		checks = []check{
			{flow{iif: t.Interface, oif: t.Egress, ctState: "new"},
				fmt.Sprintf(`no rule clearly accepts traffic from %s; for example: iifname "plait*" accept`, t.Interface)},
			{flow{iif: t.Egress, oif: t.Interface, ctState: "established"},
				fmt.Sprintf("no rule clearly accepts replies to %s; for example: ct state established,related accept", t.Interface)},
		}
	}
	var out []string
	for _, c := range checks {
		accepted := false
		for _, item := range doc.Nftables {
			if item.Rule != nil && mayAccept(item.Rule.Expr, c.f) {
				accepted = true
				break
			}
		}
		if !accepted {
			out = append(out, c.message)
		}
	}
	return out, nil
}

// mayAccept reports whether a rule could accept f: it ends in accept, jump,
// or goto, and none of its matches is known to exclude f. Matches it cannot
// evaluate count as possibly matching.
func mayAccept(exprs []map[string]json.RawMessage, f flow) bool {
	verdict := false
	for _, e := range exprs {
		for key, raw := range e {
			switch key {
			case "accept", "jump", "goto":
				verdict = true
			case "drop", "reject", "return":
				return false
			case "match":
				if excludes(raw, f) {
					return false
				}
			}
		}
	}
	return verdict
}

// excludes reports whether a match expression is known not to match f.
func excludes(raw json.RawMessage, f flow) bool {
	var m struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	var ref string
	if json.Unmarshal(m.Right, &ref) == nil && strings.HasPrefix(ref, "@") {
		return false // named set: contents unknown here
	}
	var left struct {
		Meta    *struct{ Key string }             `json:"meta"`
		Payload *struct{ Protocol, Field string } `json:"payload"`
		Ct      *struct{ Key string }             `json:"ct"`
	}
	if json.Unmarshal(m.Left, &left) != nil {
		return false
	}
	anyValue := func(one func(json.RawMessage) bool) bool {
		hit := false
		forEachValue(m.Right, func(v json.RawMessage) { hit = hit || one(v) })
		return hit
	}
	isString := func(want string) func(json.RawMessage) bool {
		return func(v json.RawMessage) bool {
			var s string
			return json.Unmarshal(v, &s) == nil && s == want
		}
	}

	var hit bool // the expression matches f
	switch {
	case left.Meta != nil && (left.Meta.Key == "iifname" || left.Meta.Key == "oifname"):
		name := f.iif
		if left.Meta.Key == "oifname" {
			name = f.oif
		}
		hit = anyValue(func(v json.RawMessage) bool { return ifnameMatches(v, name) })
	case left.Meta != nil && (left.Meta.Key == "iif" || left.Meta.Key == "oif"):
		name := f.iif
		if left.Meta.Key == "oif" {
			name = f.oif
		}
		hit = anyValue(isString(name))
	case left.Meta != nil && left.Meta.Key == "l4proto",
		left.Payload != nil && left.Payload.Protocol == "ip" && left.Payload.Field == "protocol":
		if f.udpPort == 0 {
			return false // the flow is any protocol
		}
		hit = anyValue(isString("udp"))
	case left.Payload != nil && left.Payload.Field == "dport":
		if f.udpPort == 0 {
			return false
		}
		hit = (left.Payload.Protocol == "udp" || left.Payload.Protocol == "th") &&
			anyValue(func(v json.RawMessage) bool { return portMatches(v, f.udpPort) })
	case left.Ct != nil && left.Ct.Key == "state":
		hit = anyValue(isString(f.ctState)) || f.ctState == "established" && anyValue(isString("related"))
	default:
		return false // a match this check does not evaluate
	}
	switch m.Op {
	case "==", "in":
		return !hit
	case "!=":
		return hit
	}
	return false
}

// forEachValue calls fn for a match's right side: a single value or a set.
func forEachValue(right json.RawMessage, fn func(json.RawMessage)) {
	var set struct {
		Set []json.RawMessage `json:"set"`
	}
	var list []json.RawMessage
	switch {
	case json.Unmarshal(right, &set) == nil && set.Set != nil:
		for _, v := range set.Set {
			fn(v)
		}
	case json.Unmarshal(right, &list) == nil:
		for _, v := range list {
			fn(v)
		}
	default:
		fn(right)
	}
}

// ifnameMatches applies nft interface-name semantics: a trailing * is a
// prefix wildcard.
func ifnameMatches(v json.RawMessage, name string) bool {
	var pat string
	if json.Unmarshal(v, &pat) != nil || name == "" {
		return false
	}
	if p, ok := strings.CutSuffix(pat, "*"); ok && !strings.HasSuffix(p, `\`) {
		return strings.HasPrefix(name, p)
	}
	return pat == name
}

func portMatches(v json.RawMessage, port uint16) bool {
	var n int
	if json.Unmarshal(v, &n) == nil {
		return n == int(port)
	}
	var r struct {
		Range []int `json:"range"`
	}
	if json.Unmarshal(v, &r) == nil && len(r.Range) == 2 {
		return r.Range[0] <= int(port) && int(port) <= r.Range[1]
	}
	return false
}
