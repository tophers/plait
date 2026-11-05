// Package api serves plaitd's REST API: agent endpoints authenticated by
// site-scoped bearer credentials, and administrator endpoints authenticated
// by session cookies with CSRF protection.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"plait/internal/compiler"
	"plait/internal/controller"
	"plait/internal/model"
)

const (
	SessionCookie = "plait_session"
	maxBodyBytes  = 1 << 20
)

type Server struct {
	Svc *controller.Service
	Log *slog.Logger
	// UI, when set, serves every path outside /api/ and /healthz.
	UI http.Handler

	limiter *LoginLimiter
}

// Limiter returns the login throttle so the UI can share it.
func (s *Server) Limiter() *LoginLimiter { return s.limiter }

func New(svc *controller.Service, log *slog.Logger) *Server {
	return &Server{Svc: svc, Log: log, limiter: NewLoginLimiter()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/v1/agent/enroll", s.agentEnroll)
	mux.Handle("GET /api/v1/agent/sync", s.agent(s.agentSync))
	mux.Handle("POST /api/v1/agent/status", s.agent(s.agentStatus))
	mux.Handle("POST /api/v1/agent/credential/rotate", s.agent(s.agentRotate))

	mux.HandleFunc("POST /api/v1/admin/login", s.login)
	mux.Handle("POST /api/v1/admin/logout", s.admin(s.logout))
	mux.Handle("GET /api/v1/admin/session", s.admin(s.session))

	mux.Handle("GET /api/v1/admin/sites", s.admin(s.listSites))
	mux.Handle("POST /api/v1/admin/sites", s.admin(s.createSite))
	mux.Handle("GET /api/v1/admin/sites/{id}", s.admin(s.getSite))
	mux.Handle("PUT /api/v1/admin/sites/{id}", s.admin(s.updateSite))
	mux.Handle("POST /api/v1/admin/sites/{id}/enable", s.admin(s.setSiteEnabled(true)))
	mux.Handle("POST /api/v1/admin/sites/{id}/disable", s.admin(s.setSiteEnabled(false)))
	mux.Handle("POST /api/v1/admin/sites/{id}/enrollment-token", s.admin(s.enrollmentToken))
	mux.Handle("GET /api/v1/admin/sites/{id}/credentials", s.admin(s.siteCredentials))
	mux.Handle("POST /api/v1/admin/sites/{id}/credentials/revoke", s.admin(s.revokeCredentials))
	mux.Handle("GET /api/v1/admin/sites/{id}/status", s.admin(s.siteStatus))

	mux.Handle("GET /api/v1/admin/devices", s.admin(s.listDevices))
	mux.Handle("POST /api/v1/admin/devices", s.admin(s.enrollDevice))
	mux.Handle("GET /api/v1/admin/devices/{id}", s.admin(s.getDevice))
	mux.Handle("POST /api/v1/admin/devices/{id}/rename", s.admin(s.renameDevice))
	mux.Handle("POST /api/v1/admin/devices/{id}/enable", s.admin(s.setDeviceEnabled(true)))
	mux.Handle("POST /api/v1/admin/devices/{id}/disable", s.admin(s.setDeviceEnabled(false)))
	mux.Handle("POST /api/v1/admin/devices/{id}/retire", s.admin(s.retireDevice))
	mux.Handle("DELETE /api/v1/admin/devices/{id}", s.admin(s.deleteDevice))
	mux.Handle("POST /api/v1/admin/devices/{id}/replace-key", s.admin(s.replaceDeviceKey))
	mux.Handle("PUT /api/v1/admin/devices/{id}/settings", s.admin(s.deviceSettings))
	mux.Handle("GET /api/v1/admin/devices/{id}/profile-material", s.admin(s.profileMaterial))
	mux.Handle("POST /api/v1/admin/devices/{id}/exports", s.admin(s.recordExport))

	mux.Handle("POST /api/v1/admin/links", s.admin(s.createLink))
	mux.Handle("POST /api/v1/admin/links/{id}/enable", s.admin(s.setLinkEnabled(true)))
	mux.Handle("POST /api/v1/admin/links/{id}/disable", s.admin(s.setLinkEnabled(false)))
	mux.Handle("POST /api/v1/admin/links/{id}/rotate-psk", s.admin(s.rotatePSK))
	mux.Handle("PUT /api/v1/admin/links/{id}/keepalive", s.admin(s.linkKeepalive))

	mux.Handle("GET /api/v1/admin/audit", s.admin(s.auditLog))
	if s.UI != nil {
		mux.Handle("/", s.UI)
	}
	return s.common(mux)
}

// --- middleware ---

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// common sets security headers, disables caching (responses may carry PSKs
// or profile material), recovers panics, and logs requests without bodies,
// query strings, or headers.
func (s *Server) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Not no-referrer: under that policy browsers send "Origin: null" on
		// same-origin form posts, which the cross-origin check must reject.
		h.Set("Referrer-Policy", "same-origin")
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if p := recover(); p != nil {
				s.Log.Error("panic serving request", "method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(p))
				http.Error(rec, `{"error":"internal error"}`, http.StatusInternalServerError)
			}
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(rec, r)
	})
}

type ctxKey int

const (
	agentKey ctxKey = iota
	sessionKey
)

func (s *Server) agent(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="plait-agent"`)
			writeError(w, controller.ErrUnauthenticated, s.Log)
			return
		}
		a, err := s.Svc.AuthenticateAgent(r.Context(), strings.TrimSpace(token))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="plait-agent", error="invalid_token"`)
			writeError(w, err, s.Log)
			return
		}
		ctx := context.WithValue(r.Context(), agentKey, a)
		next(w, r.WithContext(controller.WithActor(ctx, "agent:"+a.SiteID)))
	})
}

func agentFrom(r *http.Request) *controller.Agent {
	return r.Context().Value(agentKey).(*controller.Agent)
}

// admin requires a valid session. State-changing requests must also carry the
// session's CSRF token in X-CSRF-Token and pass SameOrigin.
func (s *Server) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			writeError(w, controller.ErrUnauthenticated, s.Log)
			return
		}
		sess, err := s.Svc.Session(r.Context(), c.Value)
		if err != nil {
			writeError(w, err, s.Log)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !SameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request rejected"})
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRFToken)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next(w, r.WithContext(controller.WithActor(ctx, "admin:"+sess.Username)))
	})
}

var crossOrigin = http.NewCrossOriginProtection()

// SameOrigin rejects state-changing requests a browser marks as cross-origin:
// Sec-Fetch-Site when sent (all current browsers), otherwise Origin compared
// with Host. Requests with neither header are not from a browser and rely on
// the CSRF token alone. The API and the UI share this check.
func SameOrigin(r *http.Request) bool {
	return crossOrigin.Check(r) == nil
}

// --- login rate limiting ---

// LoginLimiter throttles failed administrator logins per username and per
// client address. The API and the UI share one instance. Each attempt counts
// as a failure from the moment it starts, so concurrent attempts cannot all
// pass the check before any of them fails; a successful login withdraws its
// entry. Blocked attempts create no entries, and entries are dropped once
// they leave the window, so memory follows the recent failure rate.
type LoginLimiter struct {
	mu        sync.Mutex
	failures  map[string][]time.Time // oldest first
	nextSweep int
}

const (
	loginWindow      = 15 * time.Minute
	loginMaxFailures = 10
	minLoginSweep    = 1024
)

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{failures: map[string][]time.Time{}, nextSweep: minLoginSweep}
}

// LoginKeys returns the limiter keys for a login attempt. Names no
// administrator could have share one key, so arbitrary strings never become
// map keys. IPv6 clients are keyed by /64, since one host typically controls
// a whole /64.
func LoginKeys(username string, r *http.Request) (userKey, ipKey string) {
	if model.ValidateName(username) != nil {
		username = ""
	}
	ip := ClientIP(r)
	if a, err := netip.ParseAddr(ip); err == nil {
		if a = a.Unmap().WithZone(""); a.Is6() {
			p, _ := a.Prefix(64)
			ip = p.String()
		} else {
			ip = a.String()
		}
	}
	return "user:" + username, "ip:" + ip
}

// recent drops k's failures older than cutoff, and k itself if none remain.
func (l *LoginLimiter) recent(k string, cutoff time.Time) []time.Time {
	ts := l.failures[k]
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	if i == len(ts) {
		delete(l.failures, k)
		return nil
	}
	if i > 0 {
		ts = ts[i:]
		l.failures[k] = ts
	}
	return ts
}

// Attempt starts a login attempt, counting it as a failure against every
// key. It reports false, recording nothing, if any key is at the limit. If
// the attempt does not fail, pass the returned time to Withdraw.
func (l *LoginLimiter) Attempt(keys ...string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-loginWindow)
	for _, k := range keys {
		if len(l.recent(k, cutoff)) >= loginMaxFailures {
			return time.Time{}, false
		}
	}
	for _, k := range keys {
		l.failures[k] = append(l.failures[k], now)
	}
	if len(l.failures) >= l.nextSweep {
		for k := range l.failures {
			l.recent(k, cutoff)
		}
		l.nextSweep = max(minLoginSweep, 2*len(l.failures))
	}
	return now, true
}

// Withdraw removes the entry Attempt recorded at time at from each key.
func (l *LoginLimiter) Withdraw(at time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		ts := l.failures[k]
		if i := slices.IndexFunc(ts, at.Equal); i >= 0 {
			ts = slices.Delete(ts, i, i+1)
		}
		if len(ts) == 0 {
			delete(l.failures, k)
		} else {
			l.failures[k] = ts
		}
	}
}

func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// ClientIP is the request's peer address (not proxy headers, which a client
// could forge).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		return &model.ValidationError{Msg: "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &model.ValidationError{Msg: "malformed JSON request body"}
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return &model.ValidationError{Msg: "request body must contain a single JSON object"}
	}
	return nil
}

var errRecovery = errors.New("controller is in recovery; desired state is withheld until an administrator completes recovery")

// writeError maps errors to statuses. Unexpected errors are logged and
// reported generically.
func writeError(w http.ResponseWriter, err error, log *slog.Logger) {
	status, msg := http.StatusInternalServerError, "internal error"
	switch {
	case model.IsValidation(err):
		status, msg = http.StatusBadRequest, err.Error()
	case errors.Is(err, controller.ErrNotFound):
		status, msg = http.StatusNotFound, "not found"
	case errors.Is(err, controller.ErrUnauthenticated), errors.Is(err, controller.ErrBadLogin):
		status, msg = http.StatusUnauthorized, err.Error()
	case errors.Is(err, controller.ErrRotationTooSoon):
		status, msg = http.StatusTooManyRequests, err.Error()
	case errors.Is(err, controller.ErrEnrollment):
		status, msg = http.StatusForbidden, err.Error()
	case errors.Is(err, compiler.ErrDeviceInactive), errors.Is(err, compiler.ErrSitePending):
		status, msg = http.StatusConflict, err.Error()
	case errors.Is(err, controller.ErrBusy):
		w.Header().Set("Retry-After", "5")
		status, msg = http.StatusServiceUnavailable, err.Error()
	case errors.Is(err, errRecovery):
		w.Header().Set("Retry-After", "60")
		status, msg = http.StatusServiceUnavailable, err.Error()
	default:
		log.Error("request failed", "err", err)
	}
	writeJSON(w, status, map[string]string{"error": msg})
}
