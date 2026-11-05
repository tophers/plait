package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"time"

	"plait/internal/protocol"
)

const (
	PollInterval = 15 * time.Second
	maxBackoff   = 5 * time.Minute
)

// Agent ties together the cache, validation, reconciliation, and controller.
type Agent struct {
	Cache     *Cache
	Validator Validator
	Recon     *Reconciler
	Client    *Client // nil: offline, cached state only
	Version   string
	Log       *slog.Logger

	desired  *protocol.SiteSnapshot
	applied  Applied
	last     Result
	rejected *protocol.ComponentError // last controller snapshot that failed acceptance
}

// Load reads cached desired and applied state. A missing cache is not an
// error; a corrupt one is reported and ignored so nothing is invented.
func (a *Agent) Load() error {
	applied, err := a.Cache.LoadApplied()
	if err != nil {
		a.Log.Error("ignoring corrupt applied-revision metadata", "err", err)
	}
	a.applied = applied
	snap, err := a.Cache.LoadDesired()
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	if err := a.Validator.Check(snap); err != nil {
		return fmt.Errorf("cached snapshot rejected: %w", err)
	}
	a.desired = snap
	return nil
}

// Accept validates and durably caches a snapshot before it is applied.
func (a *Agent) Accept(snap *protocol.SiteSnapshot) (bool, error) {
	if err := a.Validator.Check(snap); err != nil {
		return false, err
	}
	newer, err := Supersedes(a.desired, snap)
	if err != nil || !newer {
		return false, err
	}
	if err := a.Cache.StoreDesired(snap); err != nil {
		return false, fmt.Errorf("cache desired state: %w", err)
	}
	a.desired = snap
	return true, nil
}

// ReconcileCached applies the latest accepted snapshot. It always uses the
// newest cached desired state, so a failed newer revision never resurrects
// an older peer set.
func (a *Agent) ReconcileCached(ctx context.Context) (Result, bool) {
	if a.desired == nil {
		return Result{}, false
	}
	res := a.Recon.Reconcile(ctx, a.desired)
	a.last = res
	for _, c := range res.Changes {
		a.Log.Info("reconciled", "revision", res.Revision, "change", c)
	}
	for _, w := range res.Warnings {
		a.Log.Warn("reconcile warning", "revision", res.Revision, "warning", w)
	}
	for _, e := range res.Errors {
		a.Log.Error("reconcile error", "revision", res.Revision, "component", e.Component, "code", e.Code, "message", e.Message)
	}
	if res.Verified && res.Revision > a.applied.Revision {
		a.applied = Applied{Revision: res.Revision, AppliedAt: time.Now().UTC()}
		if err := a.Cache.StoreApplied(a.applied); err != nil {
			a.Log.Error("persist applied revision", "err", err)
		} else {
			a.Log.Info("revision applied", "revision", res.Revision)
		}
	}
	return res, true
}

// Status builds the report sent to the controller.
func (a *Agent) Status() *protocol.AgentStatus {
	st := &protocol.AgentStatus{
		SiteID:          a.Validator.SiteID,
		AppliedRevision: a.applied.Revision,
		ObservedAt:      time.Now().UTC(),
		AgentVersion:    a.Version,
		Errors:          []protocol.ComponentError{},
	}
	if a.desired == nil {
		st.Errors = append(st.Errors, protocol.ComponentError{Component: "config", Code: "not-ready", Message: "no valid desired state cached"})
		return st
	}
	st.AcceptedRevision = a.desired.Revision
	st.Healthy = a.last.Verified
	st.Errors = append(st.Errors, a.last.Errors...)
	if a.rejected != nil {
		st.Errors = append(st.Errors, *a.rejected)
		st.Healthy = false
	}
	st.Warnings = a.last.Warnings
	st.Peers = a.Recon.Telemetry(a.desired)
	return st
}

// Run reconciles immediately from cache, then polls the controller about
// every PollInterval with jitter. Controller failures back off, but local
// drift repair from the cache continues on every tick.
func (a *Agent) Run(ctx context.Context) error {
	if a.desired == nil {
		a.Log.Warn("not ready: no valid cached desired state; waiting for the controller")
	}
	a.ReconcileCached(ctx)

	failures := 0
	answering := false // the controller responded on the last fetch attempt
	nextFetch := time.Now()
	for {
		if a.Client != nil && !time.Now().Before(nextFetch) {
			if err := a.poll(ctx); err != nil {
				failures++
				var he *HTTPError
				answering = errors.As(err, &he)
				// Back off only from an unreachable controller; one that
				// answers (401, 503 during recovery) is polled normally.
				backoff := min(PollInterval<<min(failures, 8), maxBackoff)
				if answering {
					backoff = PollInterval
				}
				nextFetch = time.Now().Add(jitter(backoff))
				a.Log.Warn("controller unavailable; continuing from cached state", "err", err, "retry_in", backoff)
			} else {
				failures, answering = 0, true
				nextFetch = time.Now()
			}
		}
		a.ReconcileCached(ctx)
		// Keep reporting while the controller answers, even if it refuses to
		// serve desired state (e.g. during recovery, when reports reveal which
		// agents are ahead). Skip only when it is unreachable.
		if a.Client != nil && answering {
			if err := a.Client.Report(ctx, a.Status()); err != nil {
				a.Log.Warn("status report failed", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitter(PollInterval)):
		}
	}
}

func (a *Agent) poll(ctx context.Context) error {
	snap, err := a.Client.Fetch(ctx)
	if err != nil {
		return err
	}
	changed, err := a.Accept(snap)
	if err != nil {
		// A rejected snapshot is a controller-side problem; keep serving the
		// cached state and surface the error rather than applying anything.
		a.rejected = &protocol.ComponentError{Component: "config", Code: "snapshot-rejected", Message: err.Error()}
		a.Log.Error("snapshot rejected", "revision", snap.Revision, "err", err)
		return nil
	}
	a.rejected = nil
	if changed {
		a.Log.Info("accepted desired revision", "revision", snap.Revision, "peers", len(snap.Peers))
	}
	return nil
}

// jitter spreads d by ±20%.
func jitter(d time.Duration) time.Duration {
	spread := int64(d) / 5
	return d + time.Duration(rand.Int64N(2*spread+1)-spread)
}
