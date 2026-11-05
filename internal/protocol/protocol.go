// Package protocol defines the JSON documents exchanged between plaitd,
// plait-agent, and plaitctl.
package protocol

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"plait/internal/wg"
)

const (
	SnapshotSchemaVersion = 1
	ProfileSchemaVersion  = 2
)

// SiteSnapshot is the complete desired state for one site, returned by
// GET /api/v1/agent/sync. Absence of a peer from a valid snapshot means removal.
type SiteSnapshot struct {
	SchemaVersion int            `json:"schema_version"`
	SiteID        string         `json:"site_id"`
	Revision      int64          `json:"revision"`
	Interface     SiteInterface  `json:"interface"`
	Network       SiteNetwork    `json:"network"`
	Peers         []SnapshotPeer `json:"peers"`
}

type SiteInterface struct {
	Name       string `json:"name"`
	PublicKey  wg.Key `json:"public_key"`
	ListenPort uint16 `json:"listen_port"`
	MTU        int    `json:"mtu"`
}

type SiteNetwork struct {
	ClientPool      netip.Prefix   `json:"client_pool"`
	EgressInterface string         `json:"egress_interface"`
	LANPrefixes     []netip.Prefix `json:"lan_prefixes"`
	Masquerade      bool           `json:"masquerade"`
	// GatewayTCPPorts on the gateway itself that clients may reach.
	GatewayTCPPorts []uint16 `json:"gateway_tcp_ports,omitempty"`
}

type SnapshotPeer struct {
	DeviceID     string         `json:"device_id"`
	PublicKey    wg.Key         `json:"public_key"`
	AllowedIPs   []netip.Prefix `json:"allowed_ips"`
	PresharedKey wg.Key         `json:"preshared_key"`
}

// Validate checks structural integrity. It deliberately rejects a missing
// peers array so that a malformed document is never treated as "remove all".
func (s *SiteSnapshot) Validate() error {
	if s.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported snapshot schema version %d", s.SchemaVersion)
	}
	if s.SiteID == "" || s.Revision <= 0 {
		return errors.New("snapshot missing site_id or revision")
	}
	if s.Peers == nil {
		return errors.New("snapshot missing peers")
	}
	if s.Interface.PublicKey.IsZero() || s.Interface.ListenPort == 0 {
		return errors.New("snapshot interface incomplete")
	}
	for i, p := range s.Network.GatewayTCPPorts {
		if p == 0 || i > 0 && p <= s.Network.GatewayTCPPorts[i-1] {
			return errors.New("snapshot gateway TCP ports must be sorted, unique, and nonzero")
		}
	}
	seen := map[wg.Key]bool{}
	for _, p := range s.Peers {
		if p.PublicKey.IsZero() || p.PresharedKey.IsZero() {
			return errors.New("snapshot peer missing key")
		}
		if seen[p.PublicKey] {
			return fmt.Errorf("snapshot has duplicate peer for device %s", p.DeviceID)
		}
		seen[p.PublicKey] = true
		if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].Bits() != 32 || !s.Network.ClientPool.Contains(p.AllowedIPs[0].Addr()) {
			return fmt.Errorf("snapshot peer %s must have exactly one /32 inside the client pool", p.DeviceID)
		}
	}
	return nil
}

// ProfileMaterial is everything needed to build a client profile except the
// private key, which never leaves the client.
type ProfileMaterial struct {
	SchemaVersion int           `json:"schema_version"`
	DeviceID      string        `json:"device_id"`
	DeviceName    string        `json:"device_name"`
	Revision      int64         `json:"revision"`
	PublicKey     wg.Key        `json:"public_key"`
	Address       netip.Prefix  `json:"address"`
	MTU           int           `json:"mtu,omitempty"`
	DNSServers    []netip.Addr  `json:"dns_servers,omitempty"`
	SearchDomains []string      `json:"search_domains,omitempty"`
	Peers         []ProfilePeer `json:"peers"`
	Warnings      []string      `json:"warnings,omitempty"`
}

type ProfilePeer struct {
	SiteID              string         `json:"site_id"`
	SiteName            string         `json:"site_name"`
	PublicKey           wg.Key         `json:"public_key"`
	Endpoint            string         `json:"endpoint"`
	AllowedIPs          []netip.Prefix `json:"allowed_ips"`
	PresharedKey        wg.Key         `json:"preshared_key"`
	PersistentKeepalive int            `json:"persistent_keepalive"`
}

// AgentStatus is posted by an agent to POST /api/v1/agent/status. It never
// contains keys or full configurations.
type AgentStatus struct {
	SiteID           string           `json:"site_id"`
	AcceptedRevision int64            `json:"accepted_revision"`
	AppliedRevision  int64            `json:"applied_revision"`
	ObservedAt       time.Time        `json:"observed_at"`
	AgentVersion     string           `json:"agent_version"`
	Healthy          bool             `json:"healthy"`
	Errors           []ComponentError `json:"errors"`
	Warnings         []string         `json:"warnings,omitempty"`
	Peers            []PeerTelemetry  `json:"peers,omitempty"`
}

// ComponentError is a sanitized failure in one area of reconciliation.
type ComponentError struct {
	Component string `json:"component"` // config, link, wireguard, firewall, routes, host, verify
	Code      string `json:"code"`
	Message   string `json:"message"`
}

func (e ComponentError) Error() string { return e.Component + ": " + e.Message }

// PeerTelemetry is transient per-peer activity. Silence does not prove a
// client is offline, and a handshake does not prove LAN or DNS access.
type PeerTelemetry struct {
	DeviceID      string    `json:"device_id"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}
