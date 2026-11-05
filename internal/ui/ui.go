package ui

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"plait/internal/api"
	"plait/internal/compiler"
	"plait/internal/controller"
	"plait/internal/model"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const flashCookie = "plait_flash"

// maxFormBytes caps UI request bodies; every form is a few short fields.
const maxFormBytes = 64 << 10

// contentSecurityPolicy allows only same-origin scripts and styles, so the
// vendored libraries and page code are the only code that can touch a
// browser-generated private key.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

type UI struct {
	svc     *controller.Service
	log     *slog.Logger
	limiter *api.LoginLimiter
	pages   map[string]*template.Template
	static  http.Handler

	// Set when plaitd serves its own generated certificate.
	caPEM         []byte
	caFingerprint string
}

// SetControllerCA publishes the generated CA at /ca.pem (it is public) and
// adds its fingerprint to gateway enrollment commands.
func (u *UI) SetControllerCA(pemBytes []byte, fingerprint string) {
	u.caPEM, u.caFingerprint = pemBytes, fingerprint
}

func (u *UI) caCert(w http.ResponseWriter, r *http.Request) {
	if u.caPEM == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="plait-controller-ca.pem"`)
	w.Write(u.caPEM)
}

func New(svc *controller.Service, log *slog.Logger, limiter *api.LoginLimiter) (*UI, error) {
	u := &UI{svc: svc, log: log, limiter: limiter, pages: map[string]*template.Template{}}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		base := path.Base(name)
		if base == "layout.html" || base == "partials.html" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", name)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", base, err)
		}
		u.pages[strings.TrimSuffix(base, ".html")] = t
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	u.static = http.StripPrefix("/static/", http.FileServerFS(sub))
	return u, nil
}

func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", u.static)
	mux.HandleFunc("GET /ca.pem", u.caCert)
	mux.HandleFunc("GET /login", u.loginPage)
	mux.HandleFunc("POST /login", u.loginSubmit)
	mux.Handle("POST /logout", u.auth(u.logout))

	mux.Handle("GET /{$}", u.auth(u.dashboard))
	mux.Handle("GET /sites", u.auth(u.sitesPage))
	mux.Handle("GET /sites/new", u.auth(u.siteNewPage))
	mux.Handle("POST /sites", u.auth(u.siteCreate))
	mux.Handle("GET /sites/{id}", u.auth(u.sitePage))
	mux.Handle("GET /sites/{id}/status", u.auth(u.siteStatusPartial))
	mux.Handle("POST /sites/{id}", u.auth(u.siteUpdate))
	mux.Handle("POST /sites/{id}/enable", u.auth(u.siteSetEnabled(true)))
	mux.Handle("POST /sites/{id}/disable", u.auth(u.siteSetEnabled(false)))
	mux.Handle("POST /sites/{id}/enrollment-token", u.auth(u.siteEnrollmentToken))
	mux.Handle("POST /sites/{id}/credentials/revoke", u.auth(u.siteRevokeCredentials))

	mux.Handle("GET /devices", u.auth(u.devicesPage))
	mux.Handle("GET /devices/new", u.auth(u.deviceNewPage))
	mux.Handle("GET /devices/{id}", u.auth(u.devicePage))
	mux.Handle("POST /devices/{id}/rename", u.auth(u.deviceRename))
	mux.Handle("POST /devices/{id}/enable", u.auth(u.deviceSetEnabled(true)))
	mux.Handle("POST /devices/{id}/disable", u.auth(u.deviceSetEnabled(false)))
	mux.Handle("POST /devices/{id}/retire", u.auth(u.deviceRetire))
	mux.Handle("POST /devices/{id}/delete", u.auth(u.deviceDelete))
	mux.Handle("POST /devices/{id}/settings", u.auth(u.deviceSettings))
	mux.Handle("POST /devices/{id}/links", u.auth(u.deviceAddLink))
	mux.Handle("POST /links/{id}/enable", u.auth(u.linkAction("enable")))
	mux.Handle("POST /links/{id}/disable", u.auth(u.linkAction("disable")))
	mux.Handle("POST /links/{id}/rotate-psk", u.auth(u.linkAction("rotate-psk")))
	mux.Handle("POST /links/{id}/keepalive", u.auth(u.linkAction("keepalive")))

	mux.Handle("GET /audit", u.auth(u.auditPage))

	mux.Handle("GET /account", u.auth(u.accountPage))
	mux.Handle("POST /account/totp/begin", u.auth(u.totpBegin))
	mux.Handle("POST /account/totp/confirm", u.auth(u.totpConfirm))
	mux.Handle("POST /account/totp/disable", u.auth(u.totpDisable))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		mux.ServeHTTP(w, r)
	})
}

// --- auth ---

type ctxKey struct{}

// auth requires an administrator session (redirecting to the login page)
// and, for state changes, a same-origin request carrying the CSRF token in
// the csrf_token form field or the X-CSRF-Token header.
func (u *UI) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sess *controller.Session
		if c, err := r.Cookie(api.SessionCookie); err == nil {
			sess, _ = u.svc.Session(r.Context(), c.Value)
		}
		if sess == nil {
			if r.Method != http.MethodGet {
				http.Error(w, "session expired; log in again", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !api.SameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf_token")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRFToken)) != 1 {
				http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		ctx := controller.WithActor(r.Context(), "admin:"+sess.Username)
		next(w, r.WithContext(withSession(ctx, sess)))
	})
}

// --- rendering ---

type page struct {
	Title    string
	Nav      string
	User     string
	CSRF     string
	Flash    string
	FlashErr bool
	Recovery bool
	Data     any
}

func (u *UI) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	p := page{Title: title, Nav: nav, Data: data}
	if sess := sessionFrom(r.Context()); sess != nil {
		p.User, p.CSRF = sess.Username, sess.CSRFToken
		p.Recovery, _ = u.svc.InRecovery(r.Context())
	}
	p.Flash, p.FlashErr = readFlash(w, r)
	u.renderPage(w, name, p, http.StatusOK)
}

func (u *UI) renderPage(w http.ResponseWriter, name string, p page, status int) {
	t, ok := u.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", p); err != nil {
		u.log.Error("render", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// partial renders a named template from a page set without the layout.
func (u *UI) partial(w http.ResponseWriter, pageName, tmpl string, data any) {
	var buf bytes.Buffer
	if err := u.pages[pageName].ExecuteTemplate(&buf, tmpl, data); err != nil {
		u.log.Error("render partial", "template", tmpl, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// Flash messages travel in a short-lived cookie rather than the URL, so a
// crafted link cannot display arbitrary text.
func setFlash(w http.ResponseWriter, msg string, isErr bool) {
	prefix := "ok:"
	if isErr {
		prefix = "err:"
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(prefix + msg)),
		Path: "/", MaxAge: 60, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func readFlash(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return "", false
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", false
	}
	s := string(b)
	if msg, ok := strings.CutPrefix(s, "err:"); ok {
		return msg, true
	}
	return strings.TrimPrefix(s, "ok:"), false
}

// done redirects after a successful or failed form submission (POST, then
// redirect, then GET). Only validation and lookup errors are shown verbatim.
func (u *UI) done(w http.ResponseWriter, r *http.Request, to string, err error, okMsg string) {
	if err != nil {
		setFlash(w, u.userError(err), true)
	} else if okMsg != "" {
		setFlash(w, okMsg, false)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (u *UI) userError(err error) string {
	switch {
	case model.IsValidation(err):
		return err.Error()
	case errors.Is(err, controller.ErrNotFound):
		return "not found"
	case errors.Is(err, compiler.ErrDeviceInactive), errors.Is(err, compiler.ErrSitePending):
		return err.Error()
	case errors.Is(err, controller.ErrBadLogin):
		return "incorrect password or authentication code"
	case errors.Is(err, controller.ErrBusy), errors.Is(err, errTooManyAttempts):
		return err.Error()
	}
	u.log.Error("ui request failed", "err", err)
	return "internal error; see the controller log"
}

// localPath returns next if it is a same-site path, otherwise "/".
func localPath(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.HasPrefix(next, "/\\") {
		return next
	}
	return "/"
}

func idPath(prefix, id string) string {
	if _, err := uuid.Parse(id); err != nil {
		return prefix
	}
	return prefix + "/" + id
}

// --- template helpers ---

var funcs = template.FuncMap{
	"ago": func(ts string) string {
		if ts == "" {
			return "never"
		}
		t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
		if err != nil {
			if t, err = time.Parse(time.RFC3339Nano, ts); err != nil {
				return ts
			}
		}
		return agoTime(t)
	},
	"agoTime": agoTime,
	"bytes": func(n int64) string {
		const unit = 1024
		if n < unit {
			return fmt.Sprintf("%d B", n)
		}
		div, exp := int64(unit), 0
		for m := n / unit; m >= unit; m /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
	},
	"join": strings.Join,
	"sub":  func(a, b int) int { return a - b },
}

func agoTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return t.UTC().Format("2006-01-02 15:04 UTC")
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
