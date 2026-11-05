package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"plait/internal/controller"
	"plait/internal/model"
	"plait/internal/wg"
)

// --- session ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Code is the current TOTP code, required once TOTP is enabled.
	Code string `json:"code,omitempty"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	userKey, ipKey := LoginKeys(req.Username, r)
	at, ok := s.limiter.Attempt(userKey, ipKey)
	if !ok {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed logins; try again later"})
		return
	}
	secret, sess, err := s.Svc.Login(r.Context(), req.Username, req.Password, req.Code)
	if err != nil {
		if errors.Is(err, controller.ErrBadLogin) {
			s.Log.Warn("failed administrator login", "remote", ClientIP(r))
		} else {
			s.limiter.Withdraw(at, userKey, ipKey)
		}
		writeError(w, err, s.Log)
		return
	}
	s.limiter.Withdraw(at, ipKey)
	s.limiter.Reset(userKey)
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: secret, Path: "/", Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, sessionView(sess))
}

func sessionView(sess *controller.Session) map[string]any {
	return map[string]any{"username": sess.Username, "csrf_token": sess.CSRFToken, "expires_at": sess.ExpiresAt.UTC()}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		s.Svc.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, sessionView(r.Context().Value(sessionKey).(*controller.Session)))
}

// --- views ---

type siteView struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	EndpointHost    string         `json:"endpoint_host"`
	ListenPort      uint16         `json:"listen_port"`
	PublicKey       string         `json:"public_key,omitempty"`
	EgressInterface string         `json:"egress_interface"`
	MTU             int            `json:"mtu"`
	Enabled         bool           `json:"enabled"`
	Pending         bool           `json:"pending_enrollment"`
	DesiredRevision int64          `json:"desired_revision"`
	Subnets         []netip.Prefix `json:"subnets"`
	GatewayTCPPorts []uint16       `json:"gateway_tcp_ports"`
}

func toSiteView(s *model.Site) siteView {
	v := siteView{ID: s.ID, Name: s.Name, EndpointHost: s.EndpointHost, ListenPort: s.ListenPort,
		EgressInterface: s.EgressInterface, MTU: s.MTU, Enabled: s.Enabled, Pending: s.Pending(),
		DesiredRevision: s.DesiredRevision, Subnets: s.Subnets, GatewayTCPPorts: s.GatewayTCPPorts}
	if v.Subnets == nil {
		v.Subnets = []netip.Prefix{}
	}
	if v.GatewayTCPPorts == nil {
		v.GatewayTCPPorts = []uint16{}
	}
	if !s.Pending() {
		v.PublicKey = s.PublicKey.String()
	}
	return v
}

type linkView struct {
	ID            string `json:"id"`
	SiteID        string `json:"site_id"`
	SiteName      string `json:"site_name"`
	Enabled       bool   `json:"enabled"`
	Effective     bool   `json:"effective"`
	Keepalive     int    `json:"persistent_keepalive"`
	SiteDesired   int64  `json:"site_desired_revision"`
	SiteApplied   int64  `json:"site_applied_revision"`
	SitePending   bool   `json:"site_change_pending"`
	SiteReachable string `json:"site_reachability"`
}

type deviceView struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	PublicKey            string       `json:"public_key"`
	Address              netip.Addr   `json:"address"`
	ClientMTU            int          `json:"client_mtu,omitempty"`
	SearchDomains        []string     `json:"search_domains,omitempty"`
	DNSServers           []netip.Addr `json:"dns_servers"`
	Enabled              bool         `json:"enabled"`
	Retired              bool         `json:"retired"`
	ProfileRevision      int64        `json:"profile_revision"`
	LastExportedRevision int64        `json:"last_exported_revision,omitempty"`
	LastExportedAt       string       `json:"last_exported_at,omitempty"`
	ChangedSinceExport   bool         `json:"changed_since_export"`
	Links                []linkView   `json:"links,omitempty"`
	// RevocationPending is true when the device has lost access at a site
	// that has not yet acknowledged applying the change.
	RevocationPending bool `json:"revocation_pending"`
}

func toDeviceView(d *model.Device, exp controller.Export, hasExport bool) deviceView {
	v := deviceView{ID: d.ID, Name: d.Name, PublicKey: d.PublicKey.String(), Address: d.AssignedIPv4,
		ClientMTU: d.ClientMTU, SearchDomains: d.SearchDomains, DNSServers: d.DNSServers, Enabled: d.Enabled,
		Retired: d.Retired, ProfileRevision: d.ProfileRevision}
	if v.DNSServers == nil {
		v.DNSServers = []netip.Addr{}
	}
	if hasExport {
		v.LastExportedRevision, v.LastExportedAt = exp.Revision, exp.At
	}
	v.ChangedSinceExport = d.Enabled && !d.Retired && v.LastExportedRevision < d.ProfileRevision
	return v
}

func pathID(r *http.Request) string { return r.PathValue("id") }

// --- sites ---

type siteRequest struct {
	Name            string   `json:"name"`
	EndpointHost    string   `json:"endpoint_host"`
	ListenPort      uint16   `json:"listen_port"`
	PublicKey       *wg.Key  `json:"public_key"`
	EgressInterface string   `json:"egress_interface"`
	MTU             int      `json:"mtu"`
	Subnets         []string `json:"subnets"`
	GatewayTCPPorts []uint16 `json:"gateway_tcp_ports"` // replaced on update; omit for none
}

func (req *siteRequest) spec() (controller.SiteSpec, error) {
	sp := controller.SiteSpec{Name: req.Name, EndpointHost: req.EndpointHost, ListenPort: req.ListenPort,
		EgressInterface: req.EgressInterface, MTU: req.MTU, GatewayTCPPorts: req.GatewayTCPPorts}
	if req.PublicKey != nil {
		sp.PublicKey = *req.PublicKey
	}
	for _, c := range req.Subnets {
		p, err := model.ParsePrefix(c)
		if err != nil {
			return sp, err
		}
		sp.Subnets = append(sp.Subnets, p)
	}
	return sp, nil
}

func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	st, err := s.Svc.State(r.Context())
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	out := []siteView{}
	for i := range st.Sites {
		out = append(out, toSiteView(&st.Sites[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var req siteRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	sp, err := req.spec()
	if err == nil {
		var id string
		if id, err = s.Svc.CreateSite(r.Context(), sp); err == nil {
			s.respondSite(w, r, id, http.StatusCreated)
			return
		}
	}
	writeError(w, err, s.Log)
}

func (s *Server) respondSite(w http.ResponseWriter, r *http.Request, id string, status int) {
	st, err := s.Svc.State(r.Context())
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	site, ok := st.Site(id)
	if !ok {
		writeError(w, controller.ErrNotFound, s.Log)
		return
	}
	writeJSON(w, status, toSiteView(site))
}

func (s *Server) getSite(w http.ResponseWriter, r *http.Request) {
	s.respondSite(w, r, pathID(r), http.StatusOK)
}

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	var req siteRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	sp, err := req.spec()
	if err == nil {
		if err = s.Svc.UpdateSite(r.Context(), pathID(r), sp); err == nil {
			s.respondSite(w, r, pathID(r), http.StatusOK)
			return
		}
	}
	writeError(w, err, s.Log)
}

func (s *Server) setSiteEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.Svc.SetSiteEnabled(r.Context(), pathID(r), enabled); err != nil {
			writeError(w, err, s.Log)
			return
		}
		s.respondSite(w, r, pathID(r), http.StatusOK)
	}
}

func (s *Server) enrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if r.ContentLength != 0 {
		if err := decode(w, r, &req); err != nil {
			writeError(w, err, s.Log)
			return
		}
	}
	ttl := controller.DefaultEnrollmentTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	tok, exp, err := s.Svc.CreateEnrollmentToken(r.Context(), pathID(r), ttl)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": exp.UTC()})
}

func (s *Server) siteCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.Svc.SiteCredentials(r.Context(), pathID(r))
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) revokeCredentials(w http.ResponseWriter, r *http.Request) {
	if err := s.Svc.RevokeSiteCredentials(r.Context(), pathID(r)); err != nil {
		writeError(w, err, s.Log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Svc.SiteStatus(r.Context(), pathID(r))
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// --- devices ---

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	st, err := s.Svc.State(r.Context())
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	exports, err := s.Svc.ExportStatus(r.Context())
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	out := []deviceView{}
	for i := range st.Devices {
		e, ok := exports[st.Devices[i].ID]
		out = append(out, toDeviceView(&st.Devices[i], e, ok))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) respondDevice(w http.ResponseWriter, r *http.Request, id string, status int) {
	ctx := r.Context()
	st, err := s.Svc.State(ctx)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	dev, ok := st.Device(id)
	if !ok {
		writeError(w, controller.ErrNotFound, s.Log)
		return
	}
	exports, err := s.Svc.ExportStatus(ctx)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	statuses, err := s.Svc.SiteStatuses(ctx)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	byID := map[string]controller.SiteStatus{}
	for _, ss := range statuses {
		byID[ss.SiteID] = ss
	}
	e, has := exports[id]
	v := toDeviceView(dev, e, has)
	for _, l := range st.Links {
		if l.DeviceID != id {
			continue
		}
		site, _ := st.Site(l.SiteID)
		ss := byID[l.SiteID]
		lv := linkView{ID: l.ID, SiteID: l.SiteID, SiteName: site.Name, Enabled: l.Enabled, Effective: st.Effective(l),
			Keepalive: l.PersistentKeepalive, SiteDesired: ss.DesiredRevision, SiteApplied: ss.AppliedRevision,
			SitePending: ss.ChangePending, SiteReachable: ss.Reachability}
		if !lv.Effective && lv.SitePending && !site.Pending() {
			v.RevocationPending = true
		}
		v.Links = append(v.Links, lv)
	}
	writeJSON(w, status, v)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

func (s *Server) enrollDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		PublicKey     wg.Key   `json:"public_key"`
		MTU           int      `json:"mtu"`
		SearchDomains []string `json:"search_domains"`
		DNSServers    []string `json:"dns_servers"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	cs := controller.ClientSettings{MTU: req.MTU, SearchDomains: req.SearchDomains}
	// Resolvers are parsed here rather than by the decoder so that a typo is
	// reported by value instead of as malformed JSON.
	for _, v := range req.DNSServers {
		a, err := netip.ParseAddr(v)
		if err != nil {
			writeError(w, &model.ValidationError{Msg: fmt.Sprintf("invalid DNS server %q", v)}, s.Log)
			return
		}
		cs.DNSServers = append(cs.DNSServers, a)
	}
	id, _, err := s.Svc.EnrollDevice(r.Context(), req.Name, req.PublicKey, cs)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, id, http.StatusCreated)
}

func (s *Server) renameDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	if err := s.Svc.RenameDevice(r.Context(), pathID(r), req.Name); err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

func (s *Server) setDeviceEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.Svc.SetDeviceEnabled(r.Context(), pathID(r), enabled); err != nil {
			writeError(w, err, s.Log)
			return
		}
		s.respondDevice(w, r, pathID(r), http.StatusOK)
	}
}

func (s *Server) retireDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.Svc.RetireDevice(r.Context(), pathID(r)); err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

// deleteDevice removes an inactive device and frees its address. force=true
// skips waiting for linked sites to confirm the removal.
func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.Svc.DeleteDevice(r.Context(), pathID(r), r.URL.Query().Get("force") == "true"); err != nil {
		writeError(w, err, s.Log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) replaceDeviceKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey wg.Key `json:"public_key"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	if err := s.Svc.ReplaceDeviceKey(r.Context(), pathID(r), req.PublicKey); err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

func (s *Server) deviceSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MTU           int          `json:"mtu"`
		SearchDomains []string     `json:"search_domains"`
		DNSServers    []netip.Addr `json:"dns_servers"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	cs := controller.ClientSettings{MTU: req.MTU, SearchDomains: req.SearchDomains, DNSServers: req.DNSServers}
	if err := s.Svc.SetClientSettings(r.Context(), pathID(r), cs); err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

// profileMaterial returns PSK-bearing profile material for local assembly.
// It contains no private key; the access is audited.
func (s *Server) profileMaterial(w http.ResponseWriter, r *http.Request) {
	m, err := s.Svc.ProfileMaterialForExport(r.Context(), pathID(r))
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) recordExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision int64 `json:"revision"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	if req.Revision <= 0 {
		writeError(w, &model.ValidationError{Msg: "revision must be positive"}, s.Log)
		return
	}
	if err := s.Svc.RecordExport(r.Context(), pathID(r), req.Revision); err != nil {
		writeError(w, err, s.Log)
		return
	}
	s.respondDevice(w, r, pathID(r), http.StatusOK)
}

// --- links ---

func (s *Server) createLink(w http.ResponseWriter, r *http.Request) {
	req := struct {
		SiteID    string `json:"site_id"`
		DeviceID  string `json:"device_id"`
		Keepalive *int   `json:"persistent_keepalive"`
	}{}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	keepalive := model.DefaultKeepalive
	if req.Keepalive != nil {
		keepalive = *req.Keepalive
	}
	id, err := s.Svc.LinkDevice(r.Context(), req.SiteID, req.DeviceID, keepalive)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) setLinkEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.Svc.SetLinkEnabled(r.Context(), pathID(r), enabled); err != nil {
			writeError(w, err, s.Log)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) rotatePSK(w http.ResponseWriter, r *http.Request) {
	if err := s.Svc.RotateLinkPSK(r.Context(), pathID(r)); err != nil {
		writeError(w, err, s.Log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) linkKeepalive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keepalive int `json:"persistent_keepalive"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, err, s.Log)
		return
	}
	if err := s.Svc.SetLinkKeepalive(r.Context(), pathID(r), req.Keepalive); err != nil {
		writeError(w, err, s.Log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.Svc.AuditLog(r.Context(), before, limit)
	if err != nil {
		writeError(w, err, s.Log)
		return
	}
	if events == nil {
		events = []controller.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}
