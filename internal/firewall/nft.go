package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

const execTimeout = 10 * time.Second

// Nft executes a trusted nft binary directly, never through a shell.
type Nft struct {
	Path string // absolute path resolved at installation, e.g. /usr/sbin/nft
}

func (n *Nft) run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	if !strings.HasPrefix(n.Path, "/") {
		return nil, fmt.Errorf("nft path %q must be absolute", n.Path)
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.Path, args...)
	cmd.Env = []string{"LC_ALL=C"}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("nft %s: timed out", args[0])
		}
		return nil, fmt.Errorf("nft %s: %v: %s", args[0], err, Sanitize(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Apply loads a rendered ruleset in one atomic nft transaction.
func (n *Nft) Apply(ctx context.Context, ruleset string) error {
	_, err := n.run(ctx, ruleset, "-f", "-")
	return err
}

// Delete removes the plait table if present.
func (n *Nft) Delete(ctx context.Context) error {
	_, err := n.run(ctx, fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", Table, Table), "-f", "-")
	return err
}

// Inspect returns the observed plait table, or nil if it does not exist.
func (n *Nft) Inspect(ctx context.Context) (*Observed, error) {
	out, err := n.run(ctx, "", "-j", "list", "tables")
	if err != nil {
		return nil, err
	}
	present, err := hasTable(out)
	if err != nil || !present {
		return nil, err
	}
	out, err = n.run(ctx, "", "-j", "list", "table", "inet", Table)
	if err != nil {
		return nil, err
	}
	return ParseObserved(out)
}

type nftDoc struct {
	Nftables []struct {
		Table *struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"table"`
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			Hook   string `json:"hook"`
			Prio   int    `json:"prio"`
			Policy string `json:"policy"`
		} `json:"chain"`
		Set *struct {
			Table string            `json:"table"`
			Name  string            `json:"name"`
			Elem  []json.RawMessage `json:"elem"`
		} `json:"set"`
		Rule *struct {
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Comment string `json:"comment"`
		} `json:"rule"`
	} `json:"nftables"`
}

func hasTable(out []byte) (bool, error) {
	var doc nftDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return false, fmt.Errorf("parse nft tables: %w", err)
	}
	for _, item := range doc.Nftables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == Table {
			return true, nil
		}
	}
	return false, nil
}

// ParseObserved parses `nft -j list table inet plait`.
func ParseObserved(out []byte) (*Observed, error) {
	var doc nftDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft table: %w", err)
	}
	o := &Observed{Chains: map[string]ObservedChain{}, Comments: map[string][]string{}}
	for _, item := range doc.Nftables {
		switch {
		case item.Chain != nil && item.Chain.Table == Table:
			c := item.Chain
			o.Chains[c.Name] = ObservedChain{Type: c.Type, Hook: c.Hook, Policy: c.Policy, Priority: c.Prio}
		case item.Rule != nil && item.Rule.Table == Table:
			// Rules without a comment are recorded as "" so they count as drift.
			o.Comments[item.Rule.Chain] = append(o.Comments[item.Rule.Chain], item.Rule.Comment)
		case item.Set != nil && item.Set.Table == Table:
			for _, raw := range item.Set.Elem {
				p, err := parseElem(raw)
				if err != nil {
					return nil, fmt.Errorf("set %s: %w", item.Set.Name, err)
				}
				switch item.Set.Name {
				case "clients":
					o.Clients = append(o.Clients, p.Addr())
				case "lans":
					o.LANs = append(o.LANs, p)
				}
			}
		}
	}
	return o, nil
}

// parseElem accepts the element forms nft emits for ipv4_addr sets: a bare
// address, {"prefix":{...}}, or {"elem":{"val":...}} wrappers.
func parseElem(raw json.RawMessage) (netip.Prefix, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, 32), nil
	}
	var obj struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Elem *struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return netip.Prefix{}, err
	}
	switch {
	case obj.Prefix != nil:
		a, err := netip.ParseAddr(obj.Prefix.Addr)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, obj.Prefix.Len), nil
	case obj.Elem != nil:
		return parseElem(obj.Elem.Val)
	}
	return netip.Prefix{}, errors.New("unsupported set element " + Sanitize(string(raw)))
}

// Sanitize bounds and strips control characters from tool output before it
// reaches logs or status reports.
func Sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return s
}
