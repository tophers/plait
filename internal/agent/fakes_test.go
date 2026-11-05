package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"plait/internal/firewall"
	"plait/internal/network"
)

// fakeHost models WireGuard, links, routes, and nftables in memory, and
// records an ordered operation log so tests can assert sequencing.
type fakeHost struct {
	ops      []string
	links    map[string]*network.LinkState
	dev      *wgtypes.Device
	routes   map[netip.Prefix]netip.Addr // destination -> preferred source
	addrs    map[string][]netip.Prefix
	observed *firewall.Observed
	applyErr error
	sysctl   map[string]string
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		links:  map[string]*network.LinkState{"enp1s0": {Exists: true, Up: true, MTU: 1500}},
		routes: map[netip.Prefix]netip.Addr{},
		addrs:  map[string][]netip.Prefix{"enp1s0": {netip.MustParsePrefix("10.15.0.1/24")}},
		sysctl: map[string]string{
			"/proc/sys/net/ipv4/ip_forward":            "1",
			"/proc/sys/net/ipv4/conf/all/rp_filter":    "1",
			"/proc/sys/net/ipv4/conf/plait0/rp_filter": "2",
		},
	}
}

func (h *fakeHost) log(format string, args ...any) {
	h.ops = append(h.ops, fmt.Sprintf(format, args...))
}

// --- network.Manager ---

func (h *fakeHost) Link(name string) (network.LinkState, error) {
	if l, ok := h.links[name]; ok {
		return *l, nil
	}
	return network.LinkState{}, nil
}

func (h *fakeHost) EnsureLink(name string, mtu int) error {
	l, ok := h.links[name]
	if ok && !l.Owned {
		return network.ErrNotOwned
	}
	if !ok {
		h.log("link create %s", name)
		l = &network.LinkState{Exists: true, Owned: true}
		h.links[name] = l
		h.dev = &wgtypes.Device{Name: name}
	}
	l.MTU, l.Up = mtu, true
	return nil
}

func (h *fakeHost) DeleteLink(name string) error {
	delete(h.links, name)
	h.dev = nil
	h.routes = map[netip.Prefix]netip.Addr{}
	return nil
}

func (h *fakeHost) LinkExists(name string) (bool, error) {
	_, ok := h.links[name]
	return ok, nil
}

func (h *fakeHost) Addrs(dev string) ([]netip.Prefix, error) {
	if _, ok := h.links[dev]; !ok {
		return nil, errors.New("no such link")
	}
	return h.addrs[dev], nil
}

func (h *fakeHost) OwnedRoutes(string) ([]network.Route, error) {
	var out []network.Route
	for p, src := range h.routes {
		out = append(out, network.Route{Dst: p, Src: src})
	}
	return out, nil
}

func (h *fakeHost) hasRoute(p string) bool {
	_, ok := h.routes[netip.MustParsePrefix(p)]
	return ok
}

func (h *fakeHost) SetRoute(_ string, r network.Route) error {
	h.log("route add %s", r.Dst)
	h.routes[r.Dst] = r.Src
	return nil
}

func (h *fakeHost) DeleteRoute(_ string, p netip.Prefix) error {
	h.log("route del %s", p)
	delete(h.routes, p)
	return nil
}

func (h *fakeHost) ConflictingRoutes(string, netip.Prefix) ([]string, error) { return nil, nil }

// --- WireGuard ---

func (h *fakeHost) Device(name string) (*wgtypes.Device, error) {
	if h.dev == nil {
		return nil, errors.New("no such device")
	}
	cp := *h.dev
	cp.Peers = slices.Clone(h.dev.Peers)
	return &cp, nil
}

func (h *fakeHost) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if cfg.ReplacePeers {
		panic("ReplacePeers must never be used")
	}
	if cfg.PrivateKey != nil {
		h.dev.PrivateKey = *cfg.PrivateKey
	}
	if cfg.ListenPort != nil {
		h.dev.ListenPort = *cfg.ListenPort
	}
	for _, pc := range cfg.Peers {
		idx := slices.IndexFunc(h.dev.Peers, func(p wgtypes.Peer) bool { return p.PublicKey == pc.PublicKey })
		short := pc.PublicKey.String()[:8]
		switch {
		case pc.Remove:
			h.log("peer remove %s", short)
			if idx >= 0 {
				h.dev.Peers = slices.Delete(h.dev.Peers, idx, idx+1)
			}
			continue
		case idx < 0 && pc.UpdateOnly:
			continue
		case idx < 0:
			h.log("peer add %s", short)
			h.dev.Peers = append(h.dev.Peers, wgtypes.Peer{PublicKey: pc.PublicKey})
			idx = len(h.dev.Peers) - 1
		default:
			h.log("peer update %s", short)
		}
		p := &h.dev.Peers[idx]
		if pc.PresharedKey != nil {
			p.PresharedKey = *pc.PresharedKey
		}
		if pc.ReplaceAllowedIPs {
			p.AllowedIPs = nil
		}
		p.AllowedIPs = append(p.AllowedIPs, pc.AllowedIPs...)
		if pc.PersistentKeepaliveInterval != nil {
			p.PersistentKeepaliveInterval = *pc.PersistentKeepaliveInterval
		}
		if pc.Endpoint != nil {
			p.Endpoint = pc.Endpoint
		}
	}
	return nil
}

func (h *fakeHost) setEndpoint(key wgtypes.Key, ep string) {
	for i := range h.dev.Peers {
		if h.dev.Peers[i].PublicKey == key {
			addr, _ := net.ResolveUDPAddr("udp", ep)
			h.dev.Peers[i].Endpoint = addr
		}
	}
}

// --- Firewall ---

func (h *fakeHost) Apply(_ context.Context, ruleset string) error {
	if h.applyErr != nil {
		return h.applyErr
	}
	h.log("firewall apply")
	h.observed = parseRendered(ruleset)
	return nil
}

func (h *fakeHost) Delete(context.Context) error {
	h.observed = nil
	return nil
}

func (h *fakeHost) Inspect(context.Context) (*firewall.Observed, error) { return h.observed, nil }

func (h *fakeHost) ForeignBlockers(context.Context, firewall.Traffic) ([]string, error) {
	return nil, nil
}

func (h *fakeHost) readFile(path string) ([]byte, error) {
	if v, ok := h.sysctl[path]; ok {
		return []byte(v + "\n"), nil
	}
	return nil, errors.New("not found")
}

var (
	chainRe   = regexp.MustCompile(`(?s)chain (\w+) \{\n\t\ttype (\w+) hook (\w+) priority (\w+); policy (\w+);\n(.*?)\n\t\}`)
	commentRe = regexp.MustCompile(`comment "([^"]+)"`)
	setRe     = regexp.MustCompile(`(?s)set (\w+) \{.*?(?:elements = \{ ([^}]*) \})?\n\t\}`)
)

// parseRendered turns firewall.Render output into the Observed state nft
// would report after loading it.
func parseRendered(s string) *firewall.Observed {
	o := &firewall.Observed{Chains: map[string]firewall.ObservedChain{}, Comments: map[string][]string{}}
	prio := map[string]int{"filter": 0, "srcnat": 100}
	for _, m := range chainRe.FindAllStringSubmatch(s, -1) {
		o.Chains[m[1]] = firewall.ObservedChain{Type: m[2], Hook: m[3], Priority: prio[m[4]], Policy: m[5]}
		for _, c := range commentRe.FindAllStringSubmatch(m[6], -1) {
			o.Comments[m[1]] = append(o.Comments[m[1]], c[1])
		}
	}
	for _, m := range setRe.FindAllStringSubmatch(s, -1) {
		if m[2] == "" {
			continue
		}
		for _, e := range strings.Split(m[2], ", ") {
			switch m[1] {
			case "clients":
				o.Clients = append(o.Clients, netip.MustParseAddr(e))
			case "lans":
				o.LANs = append(o.LANs, netip.MustParsePrefix(e))
			}
		}
	}
	return o
}
