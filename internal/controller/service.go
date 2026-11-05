// Package controller implements plaitd's administrative operations on stored
// intent. Every mutation runs in one immediate transaction that validates the
// complete resulting state and bumps exactly the revisions whose compiled
// output changed.
package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"plait/internal/compiler"
	"plait/internal/model"
	"plait/internal/protocol"
	"plait/internal/secrets"
	"plait/internal/store"
	"plait/internal/store/db"
	"plait/internal/wg"
)

var ErrNotFound = compiler.ErrNotFound

type Service struct {
	store  *store.Store
	pool   model.Pool
	sealer *secrets.Sealer
	now    func() time.Time
	live   *liveStatus
}

func New(st *store.Store, pool model.Pool, sealer *secrets.Sealer) (*Service, error) {
	if err := pool.Validate(); err != nil {
		return nil, err
	}
	return &Service{store: st, pool: pool, sealer: sealer, now: time.Now, live: newLiveStatus()}, nil
}

// SetClock replaces the time source; for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// State returns a consistent snapshot of all stored intent.
func (s *Service) State(ctx context.Context) (*model.State, error) {
	var st *model.State
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		st, err = store.LoadState(ctx, q, s.pool, s.sealer)
		return err
	})
	return st, err
}

// mutate applies fn, validates the full resulting state, bumps revisions of
// sites and devices whose compiled configuration changed, and records ev in
// the audit log, all in one transaction. Names, warnings, and other
// presentation-only fields never cause a bump.
func (s *Service) mutate(ctx context.Context, ev *auditEvent, fn func(q *db.Queries, before *model.State) error) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		before, err := store.LoadState(ctx, q, s.pool, s.sealer)
		if err != nil {
			return err
		}
		if err := fn(q, before); err != nil {
			return err
		}
		after, err := store.LoadState(ctx, q, s.pool, s.sealer)
		if err != nil {
			return err
		}
		if err := compiler.Validate(after); err != nil {
			return err
		}
		for _, site := range before.Sites {
			if _, ok := after.Site(site.ID); ok && siteFingerprint(before, site.ID) != siteFingerprint(after, site.ID) {
				if err := q.BumpSiteRevision(ctx, site.ID); err != nil {
					return err
				}
			}
		}
		for _, dev := range before.Devices {
			if _, ok := after.Device(dev.ID); ok && deviceFingerprint(before, dev.ID) != deviceFingerprint(after, dev.ID) {
				if err := q.BumpDeviceProfileRevision(ctx, dev.ID); err != nil {
					return err
				}
			}
		}
		return s.audit(ctx, q, ev)
	})
}

func siteFingerprint(st *model.State, id string) string {
	snap, err := compiler.SiteSnapshot(st, id)
	if err != nil {
		return ""
	}
	snap.Revision = 0
	b, _ := json.Marshal(snap)
	return string(b)
}

func deviceFingerprint(st *model.State, id string) string {
	m, err := compiler.ProfileMaterial(st, id)
	if err != nil {
		return "" // inactive devices have no profile
	}
	m.Revision, m.DeviceName, m.Warnings = 0, "", nil
	for i := range m.Peers {
		m.Peers[i].SiteName = ""
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func notFound(kind, id string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s %s: %w", kind, id, ErrNotFound)
	}
	return err
}

func uniqueAsValidation(err error, msg string) error {
	if store.IsUniqueViolation(err) {
		return &model.ValidationError{Msg: msg}
	}
	return err
}

func nullKey(k wg.Key) sql.NullString {
	if k.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: k.String(), Valid: true}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// --- Sites ---

type SiteSpec struct {
	Name            string
	EndpointHost    string
	ListenPort      uint16
	PublicKey       wg.Key
	EgressInterface string
	MTU             int
	Subnets         []netip.Prefix
	GatewayTCPPorts []uint16
}

func (sp *SiteSpec) normalize(pool model.Pool) error {
	if sp.ListenPort == 0 {
		sp.ListenPort = model.DefaultListenPort
	}
	if sp.MTU == 0 {
		sp.MTU = model.DefaultSiteMTU
	}
	if err := model.ValidateName(sp.Name); err != nil {
		return err
	}
	if err := model.ValidateEndpointHost(sp.EndpointHost); err != nil {
		return err
	}
	if err := model.ValidateInterfaceName(sp.EgressInterface); err != nil {
		return err
	}
	if err := model.ValidateMTU(sp.MTU); err != nil {
		return err
	}
	subnets, err := model.ValidateSiteSubnets(pool, sp.Subnets)
	if err != nil {
		return err
	}
	sp.Subnets = subnets
	ports, err := model.NormalizeTCPPorts(sp.GatewayTCPPorts)
	if err != nil {
		return err
	}
	sp.GatewayTCPPorts = ports
	return nil
}

func (s *Service) CreateSite(ctx context.Context, sp SiteSpec) (string, error) {
	if err := sp.normalize(s.pool); err != nil {
		return "", err
	}
	id := uuid.NewString()
	ev := &auditEvent{Action: "site.create", TargetType: "site", TargetID: id,
		Details: map[string]any{"name": sp.Name, "endpoint": sp.EndpointHost, "subnets": sp.Subnets, "pending": sp.PublicKey.IsZero(),
			"gateway_tcp_ports": model.FormatTCPPorts(sp.GatewayTCPPorts)}}
	err := s.mutate(ctx, ev, func(q *db.Queries, _ *model.State) error {
		err := q.CreateSite(ctx, db.CreateSiteParams{
			ID: id, Name: sp.Name, EndpointHost: sp.EndpointHost, ListenPort: int64(sp.ListenPort),
			PublicKey: nullKey(sp.PublicKey), EgressInterface: sp.EgressInterface, Mtu: int64(sp.MTU),
		})
		if err != nil {
			return uniqueAsValidation(err, "site name or public key already in use")
		}
		if err := setGatewayPorts(ctx, q, id, sp.GatewayTCPPorts); err != nil {
			return err
		}
		return insertSubnets(ctx, q, id, sp.Subnets)
	})
	return id, err
}

func setGatewayPorts(ctx context.Context, q *db.Queries, siteID string, ports []uint16) error {
	return q.SetSiteGatewayTCPPorts(ctx, db.SetSiteGatewayTCPPortsParams{GatewayTcpPorts: model.FormatTCPPorts(ports), ID: siteID})
}

func insertSubnets(ctx context.Context, q *db.Queries, siteID string, subnets []netip.Prefix) error {
	for _, p := range subnets {
		if err := q.InsertSiteSubnet(ctx, db.InsertSiteSubnetParams{SiteID: siteID, Cidr: p.String()}); err != nil {
			return err
		}
	}
	return nil
}

// UpdateSite replaces a site's configuration, including its subnets. A zero
// public key keeps the current one; a different key is an
// administrator-approved gateway key replacement.
func (s *Service) UpdateSite(ctx context.Context, id string, sp SiteSpec) error {
	if err := sp.normalize(s.pool); err != nil {
		return err
	}
	ev := &auditEvent{Action: "site.update", TargetType: "site", TargetID: id,
		Details: map[string]any{"name": sp.Name, "endpoint": sp.EndpointHost, "listen_port": sp.ListenPort,
			"egress": sp.EgressInterface, "mtu": sp.MTU, "subnets": sp.Subnets,
			"gateway_tcp_ports": model.FormatTCPPorts(sp.GatewayTCPPorts)}}
	return s.mutate(ctx, ev, func(q *db.Queries, before *model.State) error {
		cur, ok := before.Site(id)
		if !ok {
			return fmt.Errorf("site %s: %w", id, ErrNotFound)
		}
		if sp.PublicKey.IsZero() {
			sp.PublicKey = cur.PublicKey
		} else if !sp.PublicKey.Equal(cur.PublicKey) {
			ev.Details.(map[string]any)["gateway_key_replaced"] = true
		}
		if err := q.RenameSite(ctx, db.RenameSiteParams{Name: sp.Name, ID: id}); err != nil {
			return uniqueAsValidation(err, "site name already in use")
		}
		err := q.UpdateSiteNetwork(ctx, db.UpdateSiteNetworkParams{
			EndpointHost: sp.EndpointHost, ListenPort: int64(sp.ListenPort), PublicKey: nullKey(sp.PublicKey),
			EgressInterface: sp.EgressInterface, Mtu: int64(sp.MTU), ID: id,
		})
		if err != nil {
			return uniqueAsValidation(err, "site public key already in use")
		}
		if err := setGatewayPorts(ctx, q, id, sp.GatewayTCPPorts); err != nil {
			return err
		}
		if err := q.DeleteSiteSubnets(ctx, id); err != nil {
			return err
		}
		return insertSubnets(ctx, q, id, sp.Subnets)
	})
}

// SetSiteEnabled disables (drains) or re-enables a site. A disabled site's
// snapshot carries an explicit empty peer set; its credential stays valid so
// the agent can receive that change.
func (s *Service) SetSiteEnabled(ctx context.Context, id string, enabled bool) error {
	action := "site.disable"
	if enabled {
		action = "site.enable"
	}
	return s.mutate(ctx, &auditEvent{Action: action, TargetType: "site", TargetID: id}, func(q *db.Queries, before *model.State) error {
		site, ok := before.Site(id)
		if !ok {
			return fmt.Errorf("site %s: %w", id, ErrNotFound)
		}
		if site.Enabled == enabled {
			return nil
		}
		return q.SetSiteEnabled(ctx, db.SetSiteEnabledParams{Enabled: boolInt(enabled), ID: id})
	})
}

// SiteSnapshot compiles the desired state an agent should apply.
func (s *Service) SiteSnapshot(ctx context.Context, siteID string) (*protocol.SiteSnapshot, error) {
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	return compiler.SiteSnapshot(st, siteID)
}

// --- Devices ---

// EnrollDevice registers a client public key and reserves the lowest free
// address in the pool. The controller never sees the private key.
// EnrollDevice creates a device with its client settings in one change, so a
// new device can be exported without a later settings edit.
func (s *Service) EnrollDevice(ctx context.Context, name string, publicKey wg.Key, cs ClientSettings) (string, netip.Addr, error) {
	if err := model.ValidateName(name); err != nil {
		return "", netip.Addr{}, err
	}
	if publicKey.IsZero() {
		return "", netip.Addr{}, &model.ValidationError{Msg: "device public key is required"}
	}
	if err := cs.validate(); err != nil {
		return "", netip.Addr{}, err
	}
	id := uuid.NewString()
	var addr netip.Addr
	ev := &auditEvent{Action: "device.enroll", TargetType: "device", TargetID: id}
	err := s.mutate(ctx, ev, func(q *db.Queries, _ *model.State) error {
		assigned, err := q.ListAssignedIPv4(ctx)
		if err != nil {
			return err
		}
		used := make(map[netip.Addr]bool, len(assigned))
		for _, a := range assigned {
			if ip, err := netip.ParseAddr(a); err == nil {
				used[ip] = true
			}
		}
		addr, err = s.pool.LowestFree(used)
		if err != nil {
			return &model.ValidationError{Msg: err.Error()}
		}
		ev.Details = map[string]any{"name": name, "address": addr.String(), "mtu": cs.MTU, "search_domains": cs.SearchDomains, "dns_servers": cs.DNSServers}
		err = q.CreateDevice(ctx, db.CreateDeviceParams{ID: id, Name: name, PublicKey: publicKey.String(), AssignedIpv4: addr.String()})
		if err := uniqueAsValidation(err, "device name or public key already in use"); err != nil {
			return err
		}
		return writeClientSettings(ctx, q, id, cs)
	})
	if err != nil {
		return "", netip.Addr{}, err
	}
	return id, addr, nil
}

func (s *Service) withDevice(ctx context.Context, id, action string, details any, fn func(q *db.Queries, dev *model.Device) error) error {
	ev := &auditEvent{Action: action, TargetType: "device", TargetID: id, Details: details}
	return s.mutate(ctx, ev, func(q *db.Queries, before *model.State) error {
		dev, ok := before.Device(id)
		if !ok {
			return fmt.Errorf("device %s: %w", id, ErrNotFound)
		}
		return fn(q, dev)
	})
}

func (s *Service) RenameDevice(ctx context.Context, id, name string) error {
	if err := model.ValidateName(name); err != nil {
		return err
	}
	return s.withDevice(ctx, id, "device.rename", map[string]any{"name": name}, func(q *db.Queries, _ *model.Device) error {
		return uniqueAsValidation(q.RenameDevice(ctx, db.RenameDeviceParams{Name: name, ID: id}), "device name already in use")
	})
}

func (s *Service) SetDeviceEnabled(ctx context.Context, id string, enabled bool) error {
	action := "device.disable"
	if enabled {
		action = "device.enable"
	}
	return s.withDevice(ctx, id, action, nil, func(q *db.Queries, dev *model.Device) error {
		if dev.Retired && enabled {
			return &model.ValidationError{Msg: "a retired device cannot be re-enabled"}
		}
		return q.SetDeviceEnabled(ctx, db.SetDeviceEnabledParams{Enabled: boolInt(enabled), ID: id})
	})
}

// RetireDevice removes a device from all sites permanently. Its address
// reservation is retained and never reused in v1.
func (s *Service) RetireDevice(ctx context.Context, id string) error {
	return s.withDevice(ctx, id, "device.retire", nil, func(q *db.Queries, _ *model.Device) error {
		return q.RetireDevice(ctx, id)
	})
}

// DeleteDevice removes a disabled or retired device, its links and PSKs, and
// its settings, so its address can be assigned again. Each site it was linked
// to must first apply a revision without it; until then that gateway still
// accepts the old key at the address. force skips the check for gateways that
// will never report again. The audit history is kept.
func (s *Service) DeleteDevice(ctx context.Context, id string, force bool) error {
	unconfirmed, err := s.unconfirmedRemovals(ctx, id)
	if err != nil {
		return err
	}
	if len(unconfirmed) > 0 && !force {
		return &model.ValidationError{Msg: fmt.Sprintf(
			"%s %s not yet applied this device's removal and may still accept its key; wait for it, or delete anyway",
			strings.Join(unconfirmed, ", "), pluralHas(len(unconfirmed)))}
	}
	ev := &auditEvent{Action: "device.delete", TargetType: "device", TargetID: id}
	return s.mutate(ctx, ev, func(q *db.Queries, before *model.State) error {
		dev, ok := before.Device(id)
		if !ok {
			return fmt.Errorf("device %s: %w", id, ErrNotFound)
		}
		if dev.Enabled && !dev.Retired {
			return &model.ValidationError{Msg: "disable or retire the device before deleting it"}
		}
		ev.Details = map[string]any{"name": dev.Name, "address": dev.AssignedIPv4.String(),
			"public_key": dev.PublicKey.String(), "unconfirmed_sites": unconfirmed}
		for _, del := range []func(context.Context, string) error{
			q.DeleteDeviceLinks, q.DeleteDeviceDNSServers, q.DeleteDeviceSearchDomains, q.DeleteDevice,
		} {
			if err := del(ctx, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// unconfirmedRemovals names the enrolled sites linked to an inactive device
// that have not applied their latest revision, so may still hold its peer.
func (s *Service) unconfirmedRemovals(ctx context.Context, id string) ([]string, error) {
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	dev, ok := st.Device(id)
	if !ok {
		return nil, fmt.Errorf("device %s: %w", id, ErrNotFound)
	}
	if dev.Enabled && !dev.Retired {
		return nil, &model.ValidationError{Msg: "disable or retire the device before deleting it"}
	}
	statuses, err := s.SiteStatuses(ctx)
	if err != nil {
		return nil, err
	}
	pending := map[string]bool{}
	for _, ss := range statuses {
		pending[ss.SiteID] = ss.ChangePending
	}
	var names []string
	for _, l := range st.Links {
		if l.DeviceID != id {
			continue
		}
		if site, ok := st.Site(l.SiteID); ok && !site.Pending() && pending[site.ID] {
			names = append(names, site.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func pluralHas(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

// ReplaceDeviceKey binds a new public key to the device, invalidating the old
// identity at every linked site while preserving its address.
func (s *Service) ReplaceDeviceKey(ctx context.Context, id string, publicKey wg.Key) error {
	if publicKey.IsZero() {
		return &model.ValidationError{Msg: "device public key is required"}
	}
	return s.withDevice(ctx, id, "device.replace_key", map[string]any{"public_key": publicKey.String()}, func(q *db.Queries, dev *model.Device) error {
		if dev.Retired {
			return &model.ValidationError{Msg: "cannot replace the key of a retired device"}
		}
		err := q.ReplaceDeviceKey(ctx, db.ReplaceDeviceKeyParams{PublicKey: publicKey.String(), ID: id})
		return uniqueAsValidation(err, "public key already in use")
	})
}

// ClientSettings are per-device profile options. MTU 0 omits MTU and lets the
// client choose; it is independent of any gateway MTU.
type ClientSettings struct {
	MTU           int
	SearchDomains []string
	DNSServers    []netip.Addr
}

func (cs ClientSettings) validate() error {
	if cs.MTU != 0 {
		if err := model.ValidateMTU(cs.MTU); err != nil {
			return err
		}
	}
	if err := model.ValidateSearchDomains(cs.SearchDomains); err != nil {
		return err
	}
	return model.ValidateDNSServers(cs.DNSServers)
}

func (s *Service) SetClientSettings(ctx context.Context, id string, cs ClientSettings) error {
	if err := cs.validate(); err != nil {
		return err
	}
	details := map[string]any{"mtu": cs.MTU, "search_domains": cs.SearchDomains, "dns_servers": cs.DNSServers}
	return s.withDevice(ctx, id, "device.client_settings", details, func(q *db.Queries, _ *model.Device) error {
		return writeClientSettings(ctx, q, id, cs)
	})
}

func writeClientSettings(ctx context.Context, q *db.Queries, id string, cs ClientSettings) error {
	err := q.SetDeviceClientSettings(ctx, db.SetDeviceClientSettingsParams{
		ClientMtu: sql.NullInt64{Int64: int64(cs.MTU), Valid: cs.MTU != 0},
		ID:        id,
	})
	if err != nil {
		return err
	}
	if err := q.DeleteDeviceDNSServers(ctx, id); err != nil {
		return err
	}
	for i, a := range cs.DNSServers {
		if err := q.InsertDeviceDNSServer(ctx, db.InsertDeviceDNSServerParams{DeviceID: id, Position: int64(i), Address: a.String()}); err != nil {
			return err
		}
	}
	if err := q.DeleteDeviceSearchDomains(ctx, id); err != nil {
		return err
	}
	for i, d := range cs.SearchDomains {
		if err := q.InsertDeviceSearchDomain(ctx, db.InsertDeviceSearchDomainParams{DeviceID: id, Position: int64(i), Domain: d}); err != nil {
			return err
		}
	}
	return nil
}

// ProfileMaterial compiles client profile material. It contains PSKs and must
// only be served to authenticated administrators with caching disabled.
func (s *Service) ProfileMaterial(ctx context.Context, deviceID string) (*protocol.ProfileMaterial, error) {
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	return compiler.ProfileMaterial(st, deviceID)
}

// ProfileMaterialForExport is ProfileMaterial for remote callers: because
// the material carries PSKs, each access is recorded in the audit log.
func (s *Service) ProfileMaterialForExport(ctx context.Context, deviceID string) (*protocol.ProfileMaterial, error) {
	m, err := s.ProfileMaterial(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	err = s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		return s.audit(ctx, q, &auditEvent{Action: "device.profile_material", TargetType: "device", TargetID: deviceID,
			Details: map[string]any{"revision": m.Revision}})
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// RecordExport notes that a profile revision was exported. It is not proof
// that the profile was imported or activated.
func (s *Service) RecordExport(ctx context.Context, deviceID string, revision int64) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if _, err := q.GetDevice(ctx, deviceID); err != nil {
			return notFound("device", deviceID, err)
		}
		err := q.RecordDeviceExport(ctx, db.RecordDeviceExportParams{
			LastExportedRevision: sql.NullInt64{Int64: revision, Valid: true}, ID: deviceID,
		})
		if err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "device.export", TargetType: "device", TargetID: deviceID,
			Details: map[string]any{"revision": revision}})
	})
}

// Export is the last recorded profile export for a device.
type Export struct {
	Revision int64
	At       string
}

// ExportStatus returns the last export of each device that has one.
func (s *Service) ExportStatus(ctx context.Context) (map[string]Export, error) {
	out := map[string]Export{}
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		devices, err := q.ListDevices(ctx)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.LastExportedRevision.Valid {
				out[d.ID] = Export{Revision: d.LastExportedRevision.Int64, At: d.LastExportedAt.String}
			}
		}
		return nil
	})
	return out, err
}

// --- Links ---

// LinkDevice grants a device access to all advertised prefixes at a site,
// generating a fresh PSK for the link.
func (s *Service) LinkDevice(ctx context.Context, siteID, deviceID string, keepalive int) (string, error) {
	if err := model.ValidateKeepalive(keepalive); err != nil {
		return "", err
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	ct, err := s.sealer.SealPSK(id, psk)
	if err != nil {
		return "", err
	}
	ev := &auditEvent{Action: "link.create", TargetType: "link", TargetID: id,
		Details: map[string]any{"site_id": siteID, "device_id": deviceID, "keepalive": keepalive}}
	err = s.mutate(ctx, ev, func(q *db.Queries, before *model.State) error {
		if _, ok := before.Site(siteID); !ok {
			return fmt.Errorf("site %s: %w", siteID, ErrNotFound)
		}
		dev, ok := before.Device(deviceID)
		if !ok {
			return fmt.Errorf("device %s: %w", deviceID, ErrNotFound)
		}
		if dev.Retired {
			return &model.ValidationError{Msg: "cannot link a retired device"}
		}
		err := q.CreateLink(ctx, db.CreateLinkParams{
			ID: id, SiteID: siteID, DeviceID: deviceID, PresharedKeyCiphertext: ct,
			EncryptionKeyID: s.sealer.KeyID(), PersistentKeepalive: int64(keepalive),
		})
		return uniqueAsValidation(err, "device is already linked to this site")
	})
	return id, err
}

func (s *Service) withLink(ctx context.Context, id, action string, details any, fn func(q *db.Queries) error) error {
	ev := &auditEvent{Action: action, TargetType: "link", TargetID: id, Details: details}
	return s.mutate(ctx, ev, func(q *db.Queries, _ *model.State) error {
		if _, err := q.GetLink(ctx, id); err != nil {
			return notFound("link", id, err)
		}
		return fn(q)
	})
}

func (s *Service) SetLinkEnabled(ctx context.Context, id string, enabled bool) error {
	action := "link.disable"
	if enabled {
		action = "link.enable"
	}
	return s.withLink(ctx, id, action, nil, func(q *db.Queries) error {
		return q.SetLinkEnabled(ctx, db.SetLinkEnabledParams{Enabled: boolInt(enabled), ID: id})
	})
}

func (s *Service) SetLinkKeepalive(ctx context.Context, id string, keepalive int) error {
	if err := model.ValidateKeepalive(keepalive); err != nil {
		return err
	}
	return s.withLink(ctx, id, "link.keepalive", map[string]any{"keepalive": keepalive}, func(q *db.Queries) error {
		return q.SetLinkKeepalive(ctx, db.SetLinkKeepaliveParams{PersistentKeepalive: int64(keepalive), ID: id})
	})
}

// RotateLinkPSK replaces a link's PSK. The gateway and client must both be
// updated; v1 does not provide a seamless overlap.
func (s *Service) RotateLinkPSK(ctx context.Context, id string) error {
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		return err
	}
	ct, err := s.sealer.SealPSK(id, psk)
	if err != nil {
		return err
	}
	return s.withLink(ctx, id, "link.rotate_psk", nil, func(q *db.Queries) error {
		return q.SetLinkPresharedKey(ctx, db.SetLinkPresharedKeyParams{
			PresharedKeyCiphertext: ct, EncryptionKeyID: s.sealer.KeyID(), ID: id,
		})
	})
}
