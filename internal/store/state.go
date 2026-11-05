package store

import (
	"context"
	"fmt"
	"net/netip"

	"plait/internal/model"
	"plait/internal/secrets"
	"plait/internal/store/db"
	"plait/internal/wg"
)

// LoadState reads all stored intent and decrypts link PSKs. Rows that fail to
// parse indicate corruption and are reported rather than skipped.
func LoadState(ctx context.Context, q *db.Queries, pool model.Pool, sealer *secrets.Sealer) (*model.State, error) {
	st := &model.State{Pool: pool}

	sites, err := q.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	subnets, err := q.ListSiteSubnets(ctx)
	if err != nil {
		return nil, err
	}
	bySite := map[string][]netip.Prefix{}
	for _, sn := range subnets {
		p, err := netip.ParsePrefix(sn.Cidr)
		if err != nil {
			return nil, fmt.Errorf("site %s: corrupt subnet %q", sn.SiteID, sn.Cidr)
		}
		bySite[sn.SiteID] = append(bySite[sn.SiteID], p)
	}
	for _, r := range sites {
		var key wg.Key // zero: pending enrollment
		if r.PublicKey.Valid {
			if key, err = wg.ParseKey(r.PublicKey.String); err != nil {
				return nil, fmt.Errorf("site %s: corrupt public key", r.ID)
			}
		}
		prefixes := bySite[r.ID]
		model.SortPrefixes(prefixes)
		ports, err := model.ParseTCPPorts(r.GatewayTcpPorts)
		if err != nil {
			return nil, fmt.Errorf("site %s: corrupt gateway TCP ports %q", r.ID, r.GatewayTcpPorts)
		}
		st.Sites = append(st.Sites, model.Site{
			ID:              r.ID,
			Name:            r.Name,
			EndpointHost:    r.EndpointHost,
			ListenPort:      uint16(r.ListenPort),
			PublicKey:       key,
			EgressInterface: r.EgressInterface,
			MTU:             int(r.Mtu),
			Enabled:         r.Enabled == 1,
			DesiredRevision: r.DesiredRevision,
			Subnets:         prefixes,
			GatewayTCPPorts: ports,
		})
	}

	devices, err := q.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	dnsRows, err := q.ListDeviceDNSServers(ctx)
	if err != nil {
		return nil, err
	}
	searchRows, err := q.ListDeviceSearchDomains(ctx)
	if err != nil {
		return nil, err
	}
	searchByDevice := map[string][]string{}
	for _, d := range searchRows {
		searchByDevice[d.DeviceID] = append(searchByDevice[d.DeviceID], d.Domain)
	}
	dnsByDevice := map[string][]netip.Addr{}
	for _, d := range dnsRows {
		a, err := netip.ParseAddr(d.Address)
		if err != nil {
			return nil, fmt.Errorf("device %s: corrupt DNS server %q", d.DeviceID, d.Address)
		}
		dnsByDevice[d.DeviceID] = append(dnsByDevice[d.DeviceID], a)
	}
	for _, r := range devices {
		key, err := wg.ParseKey(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("device %s: corrupt public key", r.ID)
		}
		addr, err := netip.ParseAddr(r.AssignedIpv4)
		if err != nil {
			return nil, fmt.Errorf("device %s: corrupt address %q", r.ID, r.AssignedIpv4)
		}
		st.Devices = append(st.Devices, model.Device{
			ID:              r.ID,
			Name:            r.Name,
			PublicKey:       key,
			AssignedIPv4:    addr,
			ClientMTU:       int(r.ClientMtu.Int64),
			SearchDomains:   searchByDevice[r.ID],
			DNSServers:      dnsByDevice[r.ID],
			Enabled:         r.Enabled == 1,
			Retired:         r.RetiredAt.Valid,
			ProfileRevision: r.ProfileRevision,
		})
	}

	links, err := q.ListLinks(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range links {
		psk, err := sealer.OpenPSK(r.ID, r.EncryptionKeyID, r.PresharedKeyCiphertext)
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", r.ID, err)
		}
		st.Links = append(st.Links, model.Link{
			ID:                  r.ID,
			SiteID:              r.SiteID,
			DeviceID:            r.DeviceID,
			PresharedKey:        psk,
			PersistentKeepalive: int(r.PersistentKeepalive),
			Enabled:             r.Enabled == 1,
		})
	}
	return st, nil
}
