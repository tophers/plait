package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"plait/internal/controller"
	"plait/internal/model"
)

// snapshot gathers everything the pages need in one consistent read.
type snapshot struct {
	st       *model.State
	statuses map[string]controller.SiteStatus
	exports  map[string]controller.Export
}

func (u *UI) load(ctx context.Context) (*snapshot, error) {
	st, err := u.svc.State(ctx)
	if err != nil {
		return nil, err
	}
	all, err := u.svc.SiteStatuses(ctx)
	if err != nil {
		return nil, err
	}
	exports, err := u.svc.ExportStatus(ctx)
	if err != nil {
		return nil, err
	}
	s := &snapshot{st: st, statuses: map[string]controller.SiteStatus{}, exports: exports}
	for _, ss := range all {
		s.statuses[ss.SiteID] = ss
	}
	return s, nil
}

// revocationPending: a site where the device lacks access has not yet
// acknowledged its latest change.
func (s *snapshot) revocationPending(devID string) bool {
	for _, l := range s.st.Links {
		if l.DeviceID != devID || s.st.Effective(l) {
			continue
		}
		site, ok := s.st.Site(l.SiteID)
		if ok && !site.Pending() && s.statuses[l.SiteID].ChangePending {
			return true
		}
	}
	return false
}

func (s *snapshot) changedSinceExport(d *model.Device) bool {
	return d.Enabled && !d.Retired && s.exports[d.ID].Revision < d.ProfileRevision
}

func (s *snapshot) deviceName(id string) string {
	if d, ok := s.st.Device(id); ok {
		return d.Name
	}
	return id
}

func (u *UI) fail(w http.ResponseWriter, err error) {
	http.Error(w, u.userError(err), http.StatusInternalServerError)
}

// --- dashboard ---

type siteRow struct {
	Site   *model.Site
	Status controller.SiteStatus
}

type deviceRow struct {
	Device            *model.Device
	Export            controller.Export
	ChangedSince      bool
	RevocationPending bool
	State             string
}

func deviceState(d *model.Device) string {
	switch {
	case d.Retired:
		return "retired"
	case !d.Enabled:
		return "disabled"
	}
	return "enabled"
}

func (s *snapshot) siteRows() []siteRow {
	var rows []siteRow
	for i := range s.st.Sites {
		rows = append(rows, siteRow{&s.st.Sites[i], s.statuses[s.st.Sites[i].ID]})
	}
	return rows
}

func (s *snapshot) deviceRows() []deviceRow {
	var rows []deviceRow
	for i := range s.st.Devices {
		d := &s.st.Devices[i]
		rows = append(rows, deviceRow{d, s.exports[d.ID], s.changedSinceExport(d), s.revocationPending(d.ID), deviceState(d)})
	}
	return rows
}

func (u *UI) dashboard(w http.ResponseWriter, r *http.Request) {
	s, err := u.load(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	var attention []deviceRow
	for _, d := range s.deviceRows() {
		if d.ChangedSince || d.RevocationPending {
			attention = append(attention, d)
		}
	}
	u.render(w, r, "dashboard", "Overview", "overview", map[string]any{
		"Sites": s.siteRows(), "Attention": attention, "DeviceCount": len(s.st.Devices),
	})
}

// --- sites ---

func (u *UI) sitesPage(w http.ResponseWriter, r *http.Request) {
	s, err := u.load(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	u.render(w, r, "sites", "Sites", "sites", s.siteRows())
}

type siteForm struct {
	Name, EndpointHost, ListenPort, EgressInterface, MTU, Subnets string
	GatewayTCPPorts                                               string
}

func siteFormFrom(r *http.Request) siteForm {
	return siteForm{
		Name: strings.TrimSpace(r.PostFormValue("name")), EndpointHost: strings.TrimSpace(r.PostFormValue("endpoint_host")),
		ListenPort: strings.TrimSpace(r.PostFormValue("listen_port")), EgressInterface: strings.TrimSpace(r.PostFormValue("egress_interface")),
		MTU: strings.TrimSpace(r.PostFormValue("mtu")), Subnets: r.PostFormValue("subnets"),
		GatewayTCPPorts: strings.TrimSpace(r.PostFormValue("gateway_tcp_ports")),
	}
}

func (f siteForm) spec() (controller.SiteSpec, error) {
	sp := controller.SiteSpec{Name: f.Name, EndpointHost: f.EndpointHost, EgressInterface: f.EgressInterface}
	if f.ListenPort != "" {
		p, err := strconv.ParseUint(f.ListenPort, 10, 16)
		if err != nil || p == 0 {
			return sp, &model.ValidationError{Msg: "listen port must be 1-65535"}
		}
		sp.ListenPort = uint16(p)
	}
	if f.MTU != "" {
		m, err := strconv.Atoi(f.MTU)
		if err != nil {
			return sp, &model.ValidationError{Msg: "MTU must be a number"}
		}
		sp.MTU = m
	}
	for _, field := range strings.FieldsFunc(f.Subnets, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' }) {
		p, err := model.ParsePrefix(field)
		if err != nil {
			return sp, err
		}
		sp.Subnets = append(sp.Subnets, p)
	}
	ports, err := model.ParseTCPPorts(f.GatewayTCPPorts)
	if err != nil {
		return sp, err
	}
	sp.GatewayTCPPorts = ports
	return sp, nil
}

func (u *UI) siteNewPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "site_new", "New site", "sites", siteForm{ListenPort: strconv.Itoa(model.DefaultListenPort), MTU: strconv.Itoa(model.DefaultSiteMTU)})
}

func (u *UI) siteCreate(w http.ResponseWriter, r *http.Request) {
	f := siteFormFrom(r)
	sp, err := f.spec()
	if err == nil {
		var id string
		if id, err = u.svc.CreateSite(r.Context(), sp); err == nil {
			u.done(w, r, idPath("/sites", id), nil, "Site created. Issue an enrollment token to connect its gateway.")
			return
		}
	}
	p := page{Title: "New site", Nav: "sites", Flash: u.userError(err), FlashErr: true, Data: f}
	if sess := sessionFrom(r.Context()); sess != nil {
		p.User, p.CSRF = sess.Username, sess.CSRFToken
	}
	u.renderPage(w, "site_new", p, http.StatusBadRequest)
}

type peerRow struct {
	DeviceID, DeviceName string
	LastHandshake        time.Time
	Rx, Tx               int64
}

type siteData struct {
	Site          *model.Site
	Status        controller.SiteStatus
	Form          siteForm
	MSS           int
	Peers         []peerRow
	Linked        []deviceRow
	DNSDependents []string
	Credentials   []controller.Credential
	Token         string
	TokenExpires  time.Time
	ControllerURL string
	CAFingerprint string
}

func (u *UI) siteData(r *http.Request, id string) (*siteData, error) {
	s, err := u.load(r.Context())
	if err != nil {
		return nil, err
	}
	site, ok := s.st.Site(id)
	if !ok {
		return nil, fmt.Errorf("site %s: %w", id, controller.ErrNotFound)
	}
	creds, err := u.svc.SiteCredentials(r.Context(), id)
	if err != nil {
		return nil, err
	}
	d := &siteData{Site: site, Status: s.statuses[id], MSS: site.MTU - 40, Credentials: creds}
	subnets := make([]string, len(site.Subnets))
	for i, p := range site.Subnets {
		subnets[i] = p.String()
	}
	d.Form = siteForm{Name: site.Name, EndpointHost: site.EndpointHost, ListenPort: strconv.Itoa(int(site.ListenPort)),
		EgressInterface: site.EgressInterface, MTU: strconv.Itoa(site.MTU), Subnets: strings.Join(subnets, "\n"),
		GatewayTCPPorts: model.FormatTCPPorts(site.GatewayTCPPorts)}
	for _, p := range d.Status.Peers {
		d.Peers = append(d.Peers, peerRow{p.DeviceID, s.deviceName(p.DeviceID), p.LastHandshake, p.RxBytes, p.TxBytes})
	}
	for _, l := range s.st.Links {
		if l.SiteID != id {
			continue
		}
		dev, _ := s.st.Device(l.DeviceID)
		d.Linked = append(d.Linked, deviceRow{Device: dev, State: deviceState(dev), RevocationPending: !s.st.Effective(l) && d.Status.ChangePending})
	}
	// Devices whose resolvers live in this site's LANs lose name resolution
	// if this site goes away, even while other sites keep working.
	for i := range s.st.Devices {
		dev := &s.st.Devices[i]
		if dev.Retired {
			continue
		}
		for _, dns := range dev.DNSServers {
			if containsAddr(site.Subnets, dns) {
				d.DNSDependents = append(d.DNSDependents, dev.Name)
				break
			}
		}
	}
	return d, nil
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (u *UI) sitePage(w http.ResponseWriter, r *http.Request) {
	d, err := u.siteData(r, r.PathValue("id"))
	if err != nil {
		u.notFoundOr(w, r, err)
		return
	}
	u.render(w, r, "site", d.Site.Name, "sites", d)
}

func (u *UI) notFoundOr(w http.ResponseWriter, r *http.Request, err error) {
	if u.userError(err) == "not found" {
		http.NotFound(w, r)
		return
	}
	u.fail(w, err)
}

func (u *UI) siteStatusPartial(w http.ResponseWriter, r *http.Request) {
	d, err := u.siteData(r, r.PathValue("id"))
	if err != nil {
		u.notFoundOr(w, r, err)
		return
	}
	u.partial(w, "site", "site-status", d)
}

func (u *UI) siteUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sp, err := siteFormFrom(r).spec()
	if err == nil {
		err = u.svc.UpdateSite(r.Context(), id, sp)
	}
	u.done(w, r, idPath("/sites", id), err, "Site updated. Linked devices may need a profile refresh.")
}

func (u *UI) siteSetEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !enabled && r.PostFormValue("confirm") != "yes" {
			u.done(w, r, idPath("/sites", id), &model.ValidationError{Msg: "confirm the impact before disabling the site"}, "")
			return
		}
		err := u.svc.SetSiteEnabled(r.Context(), id, enabled)
		msg := "Site enabled."
		if !enabled {
			msg = "Site disabled. Its gateway removes all peers on its next successful poll; until then the change is pending."
		}
		u.done(w, r, idPath("/sites", id), err, msg)
	}
}

func (u *UI) siteEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok, exp, err := u.svc.CreateEnrollmentToken(r.Context(), id, controller.DefaultEnrollmentTTL)
	if err != nil {
		u.done(w, r, idPath("/sites", id), err, "")
		return
	}
	d, err := u.siteData(r, id)
	if err != nil {
		u.fail(w, err)
		return
	}
	// Shown once, in this no-store response; only its hash is kept.
	d.Token, d.TokenExpires = tok, exp
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	d.ControllerURL = scheme + "://" + r.Host
	d.CAFingerprint = u.caFingerprint
	u.render(w, r, "site", d.Site.Name, "sites", d)
}

func (u *UI) siteRevokeCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := u.svc.RevokeSiteCredentials(r.Context(), id)
	u.done(w, r, idPath("/sites", id), err,
		"Credentials revoked. The gateway can no longer reach the controller but keeps serving its cached peers until changed locally or re-enrolled.")
}

// --- devices ---

func (u *UI) devicesPage(w http.ResponseWriter, r *http.Request) {
	s, err := u.load(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	u.render(w, r, "devices", "Devices", "devices", s.deviceRows())
}

func (u *UI) deviceNewPage(w http.ResponseWriter, r *http.Request) {
	st, err := u.svc.State(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	var sites []*model.Site
	for i := range st.Sites {
		if !st.Sites[i].Pending() {
			sites = append(sites, &st.Sites[i])
		}
	}
	u.render(w, r, "device_new", "New device", "devices", map[string]any{
		"Sites": sites, "Settings": clientSettingsForm{DNSMode: "none"}, "Keepalive": model.DefaultKeepalive})
}

type linkRow struct {
	Link          model.Link
	Site          *model.Site
	Effective     bool
	Status        controller.SiteStatus
	LastHandshake time.Time
	SeenAtSite    bool
}

type deviceData struct {
	Device            *model.Device
	State             string
	Export            controller.Export
	ChangedSince      bool
	RevocationPending bool
	Links             []linkRow
	Unlinked          []*model.Site
	Settings          clientSettingsForm
	Warnings          []string
	Collisions        []string
	Active            bool
}

// clientSettingsForm fills the "client-settings-fields" partial shared by the
// new-device and device pages.
type clientSettingsForm struct {
	DNSMode    string
	DNSText    string
	SearchText string
	MTU        int
}

func newClientSettingsForm(dev *model.Device) clientSettingsForm {
	dns := make([]string, len(dev.DNSServers))
	for i, a := range dev.DNSServers {
		dns[i] = a.String()
	}
	return clientSettingsForm{DNSMode: dnsMode(dev.DNSServers), DNSText: strings.Join(dns, "\n"),
		SearchText: strings.Join(dev.SearchDomains, ", "), MTU: dev.ClientMTU}
}

// commonVisitedNetworks are LANs a roaming device often joins. A site prefix
// overlapping one may be unreachable while the device is on such a network.
var commonVisitedNetworks = []string{
	"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.43.0/24", "192.168.100.0/24",
	"10.0.0.0/24", "10.0.1.0/24", "10.1.1.0/24", "172.16.0.0/24", "172.20.10.0/28",
}

func dnsMode(servers []netip.Addr) string {
	if len(servers) == 0 {
		return "none"
	}
	private, public := 0, 0
	for _, a := range servers {
		if a.IsPrivate() {
			private++
		} else {
			public++
		}
	}
	switch {
	case public == 0:
		return "internal"
	case private == 0:
		return "custom"
	}
	return "mixed"
}

func (u *UI) devicePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s, err := u.load(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	dev, ok := s.st.Device(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := &deviceData{Device: dev, State: deviceState(dev), Export: s.exports[id], ChangedSince: s.changedSinceExport(dev),
		RevocationPending: s.revocationPending(id), Settings: newClientSettingsForm(dev), Active: dev.Enabled && !dev.Retired}

	linked := map[string]bool{}
	var advertised []netip.Prefix
	for _, l := range s.st.Links {
		if l.DeviceID != id {
			continue
		}
		site, _ := s.st.Site(l.SiteID)
		row := linkRow{Link: l, Site: site, Effective: s.st.Effective(l), Status: s.statuses[l.SiteID]}
		for _, p := range row.Status.Peers {
			if p.DeviceID == id {
				row.LastHandshake, row.SeenAtSite = p.LastHandshake, true
			}
		}
		d.Links = append(d.Links, row)
		linked[l.SiteID] = true
		if row.Effective {
			advertised = append(advertised, site.Subnets...)
		}
	}
	sort.Slice(d.Links, func(i, j int) bool { return d.Links[i].Site.Name < d.Links[j].Site.Name })
	for i := range s.st.Sites {
		if !linked[s.st.Sites[i].ID] {
			d.Unlinked = append(d.Unlinked, &s.st.Sites[i])
		}
	}
	for _, c := range commonVisitedNetworks {
		cp := netip.MustParsePrefix(c)
		for _, p := range advertised {
			if p.Overlaps(cp) {
				d.Collisions = append(d.Collisions, fmt.Sprintf("%s overlaps the common network %s", p, cp))
			}
		}
	}
	if d.Active {
		// Material carries PSKs; only its warnings are used here.
		if m, err := u.svc.ProfileMaterial(r.Context(), id); err == nil {
			d.Warnings = m.Warnings
		}
	}
	u.render(w, r, "device", dev.Name, "devices", d)
}

func (u *UI) deviceRename(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := u.svc.RenameDevice(r.Context(), id, strings.TrimSpace(r.PostFormValue("name")))
	u.done(w, r, idPath("/devices", id), err, "Device renamed.")
}

func (u *UI) deviceSetEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := u.svc.SetDeviceEnabled(r.Context(), id, enabled)
		msg := "Device enabled. Use Update profile if its configuration changed."
		if !enabled {
			msg = "Device disabled. Revocation is pending until every linked site acknowledges it."
		}
		u.done(w, r, idPath("/devices", id), err, msg)
	}
}

func (u *UI) deviceRetire(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.PostFormValue("confirm") != "yes" {
		u.done(w, r, idPath("/devices", id), &model.ValidationError{Msg: "confirm before retiring: retirement is permanent"}, "")
		return
	}
	err := u.svc.RetireDevice(r.Context(), id)
	u.done(w, r, idPath("/devices", id), err, "Device retired. Its address stays reserved.")
}

func (u *UI) deviceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.PostFormValue("confirm") != "yes" {
		u.done(w, r, idPath("/devices", id), &model.ValidationError{Msg: "confirm before deleting: deletion is permanent"}, "")
		return
	}
	st, err := u.svc.State(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	dev, ok := st.Device(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := u.svc.DeleteDevice(r.Context(), id, r.PostFormValue("force") == "yes"); err != nil {
		u.done(w, r, idPath("/devices", id), err, "")
		return
	}
	u.done(w, r, "/devices", nil, fmt.Sprintf("Deleted %s. Its address %s is free for a new device.", dev.Name, dev.AssignedIPv4))
}

func (u *UI) deviceSettings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	back := idPath("/devices", id)
	cs := controller.ClientSettings{SearchDomains: strings.FieldsFunc(r.PostFormValue("search_domains"), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})}
	if v := strings.TrimSpace(r.PostFormValue("mtu")); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil {
			u.done(w, r, back, &model.ValidationError{Msg: "MTU must be a number"}, "")
			return
		}
		cs.MTU = m
	}
	mode := r.PostFormValue("dns_mode")
	if mode != "none" {
		for _, f := range strings.FieldsFunc(r.PostFormValue("dns_servers"), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' }) {
			a, err := netip.ParseAddr(f)
			if err != nil {
				u.done(w, r, back, &model.ValidationError{Msg: fmt.Sprintf("invalid DNS server %q", f)}, "")
				return
			}
			cs.DNSServers = append(cs.DNSServers, a)
		}
		if len(cs.DNSServers) == 0 {
			u.done(w, r, back, &model.ValidationError{Msg: "enter at least one resolver, or choose No tunnel DNS"}, "")
			return
		}
		if mode == "internal" && dnsMode(cs.DNSServers) != "internal" {
			u.done(w, r, back, &model.ValidationError{Msg: "Internal resolvers must be private addresses; choose Custom for public or mixed resolvers"}, "")
			return
		}
	}
	err := u.svc.SetClientSettings(r.Context(), id, cs)
	msg := "Settings saved. Use Update profile for the change to reach the device."
	if err == nil {
		if m, merr := u.svc.ProfileMaterial(r.Context(), id); merr == nil && len(m.Warnings) > 0 {
			msg += " Warning: " + strings.Join(m.Warnings, "; ")
		}
	}
	u.done(w, r, back, err, msg)
}

func (u *UI) deviceAddLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	keepalive := model.DefaultKeepalive
	if v := strings.TrimSpace(r.PostFormValue("keepalive")); v != "" {
		k, err := strconv.Atoi(v)
		if err != nil {
			u.done(w, r, idPath("/devices", id), &model.ValidationError{Msg: "keepalive must be a number"}, "")
			return
		}
		keepalive = k
	}
	_, err := u.svc.LinkDevice(r.Context(), r.PostFormValue("site_id"), id, keepalive)
	u.done(w, r, idPath("/devices", id), err, "Site access granted. Use Update profile to add the site to the device.")
}

func (u *UI) linkAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		back := idPath("/devices", r.PostFormValue("device_id"))
		var err error
		var msg string
		switch action {
		case "enable":
			err, msg = u.svc.SetLinkEnabled(r.Context(), id, true), "Access enabled."
		case "disable":
			err, msg = u.svc.SetLinkEnabled(r.Context(), id, false), "Access removed. Revocation is pending until the site acknowledges it."
		case "rotate-psk":
			if r.PostFormValue("confirm") != "yes" {
				err = &model.ValidationError{Msg: "confirm the interruption before rotating the PSK"}
				break
			}
			err, msg = u.svc.RotateLinkPSK(r.Context(), id), "PSK rotated. The link is down until the gateway applies it and the device imports a refreshed profile."
		case "keepalive":
			k, perr := strconv.Atoi(strings.TrimSpace(r.PostFormValue("keepalive")))
			if perr != nil {
				err = &model.ValidationError{Msg: "keepalive must be a number"}
				break
			}
			err, msg = u.svc.SetLinkKeepalive(r.Context(), id, k), "Keepalive updated. Use Update profile for it to take effect."
		}
		u.done(w, r, back, err, msg)
	}
}

// --- audit ---

func (u *UI) auditPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	events, err := u.svc.AuditLog(r.Context(), before, 100)
	if err != nil {
		u.fail(w, err)
		return
	}
	st, err := u.svc.State(r.Context())
	if err != nil {
		u.fail(w, err)
		return
	}
	// Targets that still exist are linked; deleted devices have no page.
	live := map[string]bool{}
	for _, s := range st.Sites {
		live[s.ID] = true
	}
	for _, d := range st.Devices {
		live[d.ID] = true
	}
	var next int64
	if len(events) == 100 {
		next = events[len(events)-1].ID
	}
	u.render(w, r, "audit", "Audit log", "audit", map[string]any{"Events": events, "Next": next, "Live": live})
}
