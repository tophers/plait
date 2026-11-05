// Package network manages the gateway's plait0 link and the /32 return
// routes Plait owns. WireGuard peer configuration is separate (wgctrl).
package network

import (
	"errors"
	"net/netip"
)

const (
	// OwnerAlias marks plait0 as created by plait-agent. An existing
	// interface without it is never taken over.
	OwnerAlias = "managed by plait-agent"
	// RouteProtocol tags routes Plait owns (rtm_protocol), so stale routes can
	// be removed without touching anyone else's.
	RouteProtocol = 77
)

var ErrNotOwned = errors.New("interface exists but is not owned by plait-agent; refusing to take it over")

// Route is a return route Plait owns. Src, when valid, is the preferred
// source address: plait0 is unnumbered, so without it the kernel picks the
// source of gateway-generated ICMP errors (Fragmentation Needed, TTL
// exceeded) from whichever interface it finds first, and a client drops
// errors from addresses outside the site's prefixes.
type Route struct {
	Dst netip.Prefix
	Src netip.Addr
}

// LinkState is the observed state of plait0.
type LinkState struct {
	Exists bool
	Owned  bool
	Up     bool
	MTU    int
}

// Manager is the host network surface the agent needs.
type Manager interface {
	Link(name string) (LinkState, error)
	// EnsureLink creates the WireGuard link if missing (marking ownership),
	// sets its MTU, and brings it up. It returns ErrNotOwned for a foreign link.
	EnsureLink(name string, mtu int) error
	DeleteLink(name string) error
	LinkExists(name string) (bool, error)
	// Addrs lists the IPv4 addresses (with prefix length) assigned to dev.
	Addrs(dev string) ([]netip.Prefix, error)
	// OwnedRoutes lists main-table routes on dev tagged with RouteProtocol.
	OwnedRoutes(dev string) ([]Route, error)
	// SetRoute adds the route, or atomically replaces one to the same
	// destination.
	SetRoute(dev string, r Route) error
	DeleteRoute(dev string, dst netip.Prefix) error
	// ConflictingRoutes describes main-table routes into pool that Plait does
	// not own on dev.
	ConflictingRoutes(dev string, pool netip.Prefix) ([]string, error)
}
