// Package compiler turns stored intent into desired site snapshots and client
// profile material. It is deterministic and has no I/O.
package compiler

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"plait/internal/model"
	"plait/internal/protocol"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDeviceInactive = errors.New("device is disabled or retired; profile export is not allowed")
	ErrSitePending    = errors.New("site gateway has not enrolled")
)

// SiteSnapshot compiles the complete desired state for one site. A disabled
// site compiles to an explicit empty peer set.
func SiteSnapshot(st *model.State, siteID string) (*protocol.SiteSnapshot, error) {
	site, ok := st.Site(siteID)
	if !ok {
		return nil, fmt.Errorf("site %s: %w", siteID, ErrNotFound)
	}
	if site.Pending() {
		return nil, ErrSitePending
	}
	snap := &protocol.SiteSnapshot{
		SchemaVersion: protocol.SnapshotSchemaVersion,
		SiteID:        site.ID,
		Revision:      site.DesiredRevision,
		Interface: protocol.SiteInterface{
			Name:       model.InterfaceName,
			PublicKey:  site.PublicKey,
			ListenPort: site.ListenPort,
			MTU:        site.MTU,
		},
		Network: protocol.SiteNetwork{
			ClientPool:      st.Pool.Prefix,
			EgressInterface: site.EgressInterface,
			LANPrefixes:     slices.Clone(site.Subnets),
			Masquerade:      true,
			GatewayTCPPorts: slices.Clone(site.GatewayTCPPorts),
		},
		Peers: []protocol.SnapshotPeer{},
	}
	if snap.Network.LANPrefixes == nil {
		snap.Network.LANPrefixes = []netip.Prefix{}
	}
	model.SortPrefixes(snap.Network.LANPrefixes)

	type peer struct {
		addr netip.Addr
		p    protocol.SnapshotPeer
	}
	var peers []peer
	for _, l := range st.Links {
		if l.SiteID != site.ID || !st.Effective(l) {
			continue
		}
		dev, _ := st.Device(l.DeviceID)
		peers = append(peers, peer{dev.AssignedIPv4, protocol.SnapshotPeer{
			DeviceID:     dev.ID,
			PublicKey:    dev.PublicKey,
			AllowedIPs:   []netip.Prefix{netip.PrefixFrom(dev.AssignedIPv4, 32)},
			PresharedKey: l.PresharedKey,
		}})
	}
	slices.SortFunc(peers, func(a, b peer) int { return a.addr.Compare(b.addr) })
	for _, p := range peers {
		snap.Peers = append(snap.Peers, p.p)
	}
	return snap, nil
}

// ProfileMaterial compiles client profile material for one device. Peers are
// ordered by site ID so renames never reorder a profile.
func ProfileMaterial(st *model.State, deviceID string) (*protocol.ProfileMaterial, error) {
	dev, ok := st.Device(deviceID)
	if !ok {
		return nil, fmt.Errorf("device %s: %w", deviceID, ErrNotFound)
	}
	if !dev.Enabled || dev.Retired {
		return nil, ErrDeviceInactive
	}
	m := &protocol.ProfileMaterial{
		SchemaVersion: protocol.ProfileSchemaVersion,
		DeviceID:      dev.ID,
		DeviceName:    dev.Name,
		Revision:      dev.ProfileRevision,
		PublicKey:     dev.PublicKey,
		Address:       netip.PrefixFrom(dev.AssignedIPv4, 32),
		MTU:           dev.ClientMTU,
		DNSServers:    slices.Clone(dev.DNSServers),
		SearchDomains: slices.Clone(dev.SearchDomains),
		Peers:         []protocol.ProfilePeer{},
	}

	type owned struct {
		prefix netip.Prefix
		site   string
	}
	var routes []owned
	for _, l := range st.Links {
		if l.DeviceID != dev.ID || !st.Effective(l) {
			continue
		}
		site, _ := st.Site(l.SiteID)
		prefixes := slices.Clone(site.Subnets)
		model.SortPrefixes(prefixes)
		for _, p := range prefixes {
			if p.Overlaps(st.Pool.Prefix) {
				return nil, &model.ValidationError{Msg: fmt.Sprintf(
					"site %s prefix %s intersects client pool %s", site.Name, p, st.Pool.Prefix)}
			}
			for _, r := range routes {
				if r.prefix.Overlaps(p) {
					return nil, &model.ValidationError{Msg: fmt.Sprintf(
						"device %s: site %s prefix %s overlaps site %s prefix %s",
						dev.Name, site.Name, p, r.site, r.prefix)}
				}
			}
			routes = append(routes, owned{p, site.Name})
		}
		m.Peers = append(m.Peers, protocol.ProfilePeer{
			SiteID:              site.ID,
			SiteName:            site.Name,
			PublicKey:           site.PublicKey,
			Endpoint:            FormatEndpoint(site.EndpointHost, site.ListenPort),
			AllowedIPs:          prefixes,
			PresharedKey:        l.PresharedKey,
			PersistentKeepalive: l.PersistentKeepalive,
		})
	}
	slices.SortFunc(m.Peers, func(a, b protocol.ProfilePeer) int { return cmp.Compare(a.SiteID, b.SiteID) })
	m.Warnings = dnsWarnings(m)
	return m, nil
}

// dnsWarnings flags resolver choices whose dependencies are easy to miss.
func dnsWarnings(m *protocol.ProfileMaterial) []string {
	var w []string
	for _, s := range m.DNSServers {
		if !s.IsPrivate() {
			continue
		}
		routed := false
		for _, p := range m.Peers {
			for _, pfx := range p.AllowedIPs {
				if pfx.Contains(s) {
					routed = true
				}
			}
		}
		if !routed {
			w = append(w, fmt.Sprintf("DNS server %s is a private address not routed through any authorized site", s))
		}
	}
	if len(m.SearchDomains) > 0 && len(m.DNSServers) == 0 {
		w = append(w, "search domains are set but no DNS servers are configured; most clients will ignore it")
	}
	return w
}

// FormatEndpoint renders host:port, bracketing IPv6 literals.
func FormatEndpoint(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// Validate checks every invariant of a complete state: the pool, each site's
// prefixes, device addresses, key uniqueness, and every effective device
// profile. Mutations must call it before committing.
func Validate(st *model.State) error {
	if err := st.Pool.Validate(); err != nil {
		return err
	}
	keys := map[string]string{}
	claim := func(key, owner string) error {
		if prev, dup := keys[key]; dup {
			return &model.ValidationError{Msg: fmt.Sprintf("public key of %s is already used by %s", owner, prev)}
		}
		keys[key] = owner
		return nil
	}
	for i := range st.Sites {
		s := &st.Sites[i]
		if _, err := model.ValidateSiteSubnets(st.Pool, s.Subnets); err != nil {
			return fmt.Errorf("site %s: %w", s.Name, err)
		}
		if !s.Pending() {
			if err := claim(s.PublicKey.String(), "site "+s.Name); err != nil {
				return err
			}
		}
	}
	addrs := map[netip.Addr]string{}
	for i := range st.Devices {
		d := &st.Devices[i]
		if !st.Pool.Allocatable(d.AssignedIPv4) {
			return &model.ValidationError{Msg: fmt.Sprintf("device %s address %s is not allocatable in pool %s", d.Name, d.AssignedIPv4, st.Pool.Prefix)}
		}
		if prev, dup := addrs[d.AssignedIPv4]; dup {
			return &model.ValidationError{Msg: fmt.Sprintf("device %s address %s is already assigned to %s", d.Name, d.AssignedIPv4, prev)}
		}
		addrs[d.AssignedIPv4] = d.Name
		if err := claim(d.PublicKey.String(), "device "+d.Name); err != nil {
			return err
		}
		if !d.Enabled || d.Retired {
			continue
		}
		if _, err := ProfileMaterial(st, d.ID); err != nil {
			return err
		}
	}
	return nil
}
