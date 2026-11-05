// Package model defines Plait's domain types and the validation shared by
// the controller, compiler, agent, and CLI.
package model

import (
	"net/netip"

	"plait/internal/wg"
)

const (
	DefaultListenPort = 51111
	DefaultSiteMTU    = 1420
	DefaultKeepalive  = 25
	InterfaceName     = "plait0"
)

// Site is a gateway location with its advertised LAN prefixes.
type Site struct {
	ID              string
	Name            string
	EndpointHost    string
	ListenPort      uint16
	PublicKey       wg.Key
	EgressInterface string
	MTU             int
	Enabled         bool
	DesiredRevision int64
	Subnets         []netip.Prefix // canonical, sorted
	// GatewayTCPPorts on the gateway host itself are reachable from
	// connected clients; everything else addressed to it is dropped.
	GatewayTCPPorts []uint16 // sorted, unique
}

// Pending reports whether the site's gateway has not yet enrolled a key.
func (s *Site) Pending() bool { return s.PublicKey.IsZero() }

// Device is a roaming client with one stable IPv4 /32 across all sites.
type Device struct {
	ID              string
	Name            string
	PublicKey       wg.Key
	AssignedIPv4    netip.Addr
	ClientMTU       int // 0: omitted, client-selected
	SearchDomains   []string
	DNSServers      []netip.Addr // ordered as configured
	Enabled         bool
	Retired         bool
	ProfileRevision int64
}

// Link authorizes one device at one site. Each link has its own PSK.
type Link struct {
	ID                  string
	SiteID              string
	DeviceID            string
	PresharedKey        wg.Key
	PersistentKeepalive int
	Enabled             bool
}

// State is a complete, decrypted view of stored intent used as compiler input.
type State struct {
	Pool    Pool
	Sites   []Site
	Devices []Device
	Links   []Link
}

func (s *State) Site(id string) (*Site, bool) {
	for i := range s.Sites {
		if s.Sites[i].ID == id {
			return &s.Sites[i], true
		}
	}
	return nil, false
}

func (s *State) Device(id string) (*Device, bool) {
	for i := range s.Devices {
		if s.Devices[i].ID == id {
			return &s.Devices[i], true
		}
	}
	return nil, false
}

// Effective reports whether a link currently grants access: the device, site,
// and link are all enabled and the device is not retired.
func (s *State) Effective(l Link) bool {
	if !l.Enabled {
		return false
	}
	site, ok := s.Site(l.SiteID)
	if !ok || !site.Enabled || site.Pending() {
		return false
	}
	dev, ok := s.Device(l.DeviceID)
	return ok && dev.Enabled && !dev.Retired
}
