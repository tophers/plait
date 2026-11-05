package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"plait/internal/firewall"
	"plait/internal/model"
	"plait/internal/protocol"
	"plait/internal/store/db"
)

const (
	// StaleAfter is how long after the last authenticated contact an agent
	// is shown as stale: four missed ~15s polls.
	StaleAfter = 60 * time.Second
	// statusWriteInterval coalesces durable last-seen updates when nothing
	// meaningful changed.
	statusWriteInterval = 5 * time.Minute
	maxReportedPeers    = 4096
)

// liveReport is transient state from the most recent agent report. It lives
// only in memory: after a controller restart everything is unknown until the
// agent reports again.
type liveReport struct {
	ReceivedAt time.Time
	Status     protocol.AgentStatus
}

type liveStatus struct {
	mu      sync.Mutex
	reports map[string]liveReport
	written map[string]time.Time // last durable write per site
}

func newLiveStatus() *liveStatus {
	return &liveStatus{reports: map[string]liveReport{}, written: map[string]time.Time{}}
}

// RecordStatus ingests an authenticated agent report. The site comes from the
// credential; a report naming another site is rejected.
func (s *Service) RecordStatus(ctx context.Context, a *Agent, st *protocol.AgentStatus) error {
	if st.SiteID != "" && st.SiteID != a.SiteID {
		return &model.ValidationError{Msg: "status site_id does not match the authenticated site"}
	}
	if st.AcceptedRevision < 0 || st.AppliedRevision < 0 || len(st.Peers) > maxReportedPeers || len(st.Errors) > 64 {
		return &model.ValidationError{Msg: "malformed status report"}
	}
	st.SiteID = a.SiteID
	st.AgentVersion = firewall.Sanitize(truncate(st.AgentVersion, 64))
	for i := range st.Errors {
		st.Errors[i] = protocol.ComponentError{
			Component: firewall.Sanitize(truncate(st.Errors[i].Component, 32)),
			Code:      firewall.Sanitize(truncate(st.Errors[i].Code, 64)),
			Message:   firewall.Sanitize(st.Errors[i].Message),
		}
	}
	if len(st.Warnings) > 64 {
		st.Warnings = st.Warnings[:64]
	}
	for i := range st.Warnings {
		st.Warnings[i] = firewall.Sanitize(st.Warnings[i])
	}
	now := s.now().UTC()

	s.live.mu.Lock()
	s.live.reports[a.SiteID] = liveReport{ReceivedAt: now, Status: *st}
	lastWrite := s.live.written[a.SiteID]
	s.live.mu.Unlock()

	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		site, err := q.GetSite(ctx, a.SiteID)
		if err != nil {
			return notFound("site", a.SiteID, err)
		}
		prev, err := q.GetSiteStatus(ctx, a.SiteID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		// Applied revisions only move forward, and never past what this
		// controller has asked for: a higher claim indicates a restored
		// controller and is surfaced via accepted_revision instead.
		applied, appliedAt := prev.AppliedRevision, prev.AppliedAt
		transition := false
		if st.AppliedRevision > prev.AppliedRevision.Int64 && st.AppliedRevision <= site.DesiredRevision {
			applied = sql.NullInt64{Int64: st.AppliedRevision, Valid: true}
			appliedAt = sql.NullString{String: fmtTime(now), Valid: true}
			transition = true
		}
		var code, msg sql.NullString
		if len(st.Errors) > 0 {
			code = sql.NullString{String: st.Errors[0].Component + "/" + st.Errors[0].Code, Valid: true}
			msg = sql.NullString{String: st.Errors[0].Message, Valid: true}
		}
		accepted := sql.NullInt64{Int64: st.AcceptedRevision, Valid: st.AcceptedRevision > 0}
		version := sql.NullString{String: st.AgentVersion, Valid: st.AgentVersion != ""}

		meaningful := transition || code != prev.LastErrorCode || accepted != prev.AcceptedRevision ||
			version != prev.AgentVersion || errors.Is(err, sql.ErrNoRows)
		if !meaningful && now.Sub(lastWrite) < statusWriteInterval {
			return nil
		}
		observed := sql.NullString{}
		if !st.ObservedAt.IsZero() {
			observed = sql.NullString{String: fmtTime(st.ObservedAt), Valid: true}
		}
		if err := q.UpsertSiteStatus(ctx, db.UpsertSiteStatusParams{
			SiteID: a.SiteID, LastSeenAt: sql.NullString{String: fmtTime(now), Valid: true},
			AppliedRevision: applied, AppliedAt: appliedAt, LastObservedAt: observed,
			LastErrorCode: code, LastErrorMessage: msg, AcceptedRevision: accepted, AgentVersion: version,
		}); err != nil {
			return err
		}
		s.live.mu.Lock()
		s.live.written[a.SiteID] = now
		s.live.mu.Unlock()
		if transition {
			return s.audit(WithActor(ctx, "agent:"+a.SiteID), q, &auditEvent{Action: "site.applied", TargetType: "site",
				TargetID: a.SiteID, Details: map[string]any{"revision": st.AppliedRevision}})
		}
		return nil
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SiteStatus separates the facts the spec requires instead of a single
// "online" flag. Unknown means no report since the controller started.
type SiteStatus struct {
	SiteID  string `json:"site_id"`
	Pending bool   `json:"pending_enrollment"`
	Enabled bool   `json:"enabled"`

	// Agent reachable: recent authenticated contact (controller receipt time).
	Reachability string `json:"reachability"` // unknown | reachable | stale
	LastContact  string `json:"last_contact,omitempty"`

	// Configuration applied: durable acknowledgments.
	DesiredRevision  int64  `json:"desired_revision"`
	AppliedRevision  int64  `json:"applied_revision"`
	AppliedAt        string `json:"applied_at,omitempty"`
	AcceptedRevision int64  `json:"accepted_revision,omitempty"`
	ChangePending    bool   `json:"change_pending"`
	AheadOfDesired   bool   `json:"agent_ahead_of_controller"`

	// Local resources healthy: from the latest live report only.
	Health     string                    `json:"health"` // unknown | healthy | unhealthy
	ObservedAt string                    `json:"observed_at,omitempty"`
	Errors     []protocol.ComponentError `json:"errors"`
	Warnings   []string                  `json:"warnings,omitempty"`
	LastError  string                    `json:"last_recorded_error,omitempty"`

	// Peer activity: transient telemetry; silence does not prove absence.
	Peers        []protocol.PeerTelemetry `json:"peers"`
	AgentVersion string                   `json:"agent_version,omitempty"`
}

// SiteStatuses reports status for every site.
func (s *Service) SiteStatuses(ctx context.Context) ([]SiteStatus, error) {
	var out []SiteStatus
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		sites, err := q.ListSites(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListSiteStatus(ctx)
		if err != nil {
			return err
		}
		byID := map[string]db.SiteStatus{}
		for _, r := range rows {
			byID[r.SiteID] = r
		}
		for _, site := range sites {
			out = append(out, s.statusView(site, byID[site.ID]))
		}
		return nil
	})
	return out, err
}

func (s *Service) SiteStatus(ctx context.Context, siteID string) (*SiteStatus, error) {
	all, err := s.SiteStatuses(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].SiteID == siteID {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("site %s: %w", siteID, ErrNotFound)
}

func (s *Service) statusView(site db.Site, row db.SiteStatus) SiteStatus {
	v := SiteStatus{
		SiteID: site.ID, Pending: !site.PublicKey.Valid, Enabled: site.Enabled == 1,
		DesiredRevision: site.DesiredRevision, AppliedRevision: row.AppliedRevision.Int64,
		AppliedAt: row.AppliedAt.String, AcceptedRevision: row.AcceptedRevision.Int64,
		Reachability: "unknown", Health: "unknown", Errors: []protocol.ComponentError{}, Peers: []protocol.PeerTelemetry{},
		AgentVersion: row.AgentVersion.String,
	}
	if row.LastErrorCode.Valid {
		v.LastError = row.LastErrorCode.String + ": " + row.LastErrorMessage.String
	}
	v.ChangePending = v.AppliedRevision < v.DesiredRevision
	v.AheadOfDesired = v.AcceptedRevision > v.DesiredRevision

	s.live.mu.Lock()
	live, ok := s.live.reports[site.ID]
	s.live.mu.Unlock()
	if !ok {
		// Durable last-seen is history, not current reachability.
		return v
	}
	v.LastContact = fmtTime(live.ReceivedAt)
	if s.now().Sub(live.ReceivedAt) <= StaleAfter {
		v.Reachability = "reachable"
	} else {
		v.Reachability = "stale"
	}
	if !live.Status.ObservedAt.IsZero() {
		v.ObservedAt = fmtTime(live.Status.ObservedAt)
	}
	if live.Status.Healthy {
		v.Health = "healthy"
	} else {
		v.Health = "unhealthy"
	}
	if v.Reachability == "stale" {
		v.Health = "unknown"
	}
	v.Errors = append(v.Errors, live.Status.Errors...)
	v.Warnings = live.Status.Warnings
	v.Peers = append(v.Peers, live.Status.Peers...)
	slices.SortFunc(v.Peers, func(a, b protocol.PeerTelemetry) int {
		if a.DeviceID < b.DeviceID {
			return -1
		}
		if a.DeviceID > b.DeviceID {
			return 1
		}
		return 0
	})
	return v
}
