package ui

import (
	"context"
	"errors"
	"net/http"

	"plait/internal/api"
	"plait/internal/controller"
)

type sessionKey struct{}

func withSession(ctx context.Context, s *controller.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func sessionFrom(ctx context.Context) *controller.Session {
	s, _ := ctx.Value(sessionKey{}).(*controller.Session)
	return s
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "login", "Log in", "", map[string]string{"Next": localPath(r.URL.Query().Get("next"))})
}

func (u *UI) loginSubmit(w http.ResponseWriter, r *http.Request) {
	username, password, code := r.PostFormValue("username"), r.PostFormValue("password"), r.PostFormValue("code")
	next := localPath(r.PostFormValue("next"))
	fail := func(msg string, status int) {
		u.renderPage(w, "login", page{Title: "Log in", Flash: msg, FlashErr: true, Data: map[string]string{"Next": next, "Username": username}}, status)
	}
	userKey, ipKey := api.LoginKeys(username, r)
	at, ok := u.limiter.Attempt(userKey, ipKey)
	if !ok {
		fail("Too many failed logins. Try again later.", http.StatusTooManyRequests)
		return
	}
	secret, sess, err := u.svc.Login(r.Context(), username, password, code)
	if errors.Is(err, controller.ErrBadLogin) {
		u.log.Warn("failed administrator login", "remote", api.ClientIP(r))
		fail("Invalid username, password, or authentication code.", http.StatusUnauthorized)
		return
	}
	if err != nil {
		u.limiter.Withdraw(at, userKey, ipKey)
		if errors.Is(err, controller.ErrBusy) {
			w.Header().Set("Retry-After", "5")
			fail("Too many logins in progress. Try again shortly.", http.StatusServiceUnavailable)
			return
		}
		u.log.Error("login", "err", err)
		fail("Login failed; see the controller log.", http.StatusInternalServerError)
		return
	}
	u.limiter.Withdraw(at, ipKey)
	u.limiter.Reset(userKey)
	http.SetCookie(w, &http.Cookie{Name: api.SessionCookie, Value: secret, Path: "/", Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(api.SessionCookie); err == nil {
		u.svc.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: api.SessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
