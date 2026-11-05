package ui

import (
	"errors"
	"net/http"

	"plait/internal/api"
	"plait/internal/controller"
)

type accountData struct {
	TOTPEnabled bool
	// Setup is set only in the response to starting setup; the secret is
	// shown once and never on a GET.
	Setup *controller.TOTPSetup
}

func (u *UI) accountPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	enabled, err := u.svc.TOTPStatus(r.Context(), sess.Username)
	if err != nil {
		u.fail(w, err)
		return
	}
	u.render(w, r, "account", "Account", "account", &accountData{TOTPEnabled: enabled})
}

// reauth runs fn, which re-checks the administrator's password, under the
// login limiter, so a stolen session cannot guess the password unthrottled.
func (u *UI) reauth(r *http.Request, fn func() error) error {
	userKey, ipKey := api.LoginKeys(sessionFrom(r.Context()).Username, r)
	at, ok := u.limiter.Attempt(userKey, ipKey)
	if !ok {
		return errTooManyAttempts
	}
	err := fn()
	if !errors.Is(err, controller.ErrBadLogin) {
		u.limiter.Withdraw(at, userKey, ipKey)
	}
	return err
}

var errTooManyAttempts = errors.New("too many failed attempts; try again later")

func (u *UI) totpBegin(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	var setup *controller.TOTPSetup
	err := u.reauth(r, func() error {
		var err error
		setup, err = u.svc.BeginTOTP(r.Context(), sess.Username, r.PostFormValue("password"))
		return err
	})
	if err != nil {
		u.done(w, r, "/account", err, "")
		return
	}
	u.render(w, r, "account", "Account", "account", &accountData{Setup: setup})
}

func (u *UI) totpConfirm(w http.ResponseWriter, r *http.Request) {
	err := u.svc.ConfirmTOTP(r.Context(), sessionFrom(r.Context()), r.PostFormValue("code"))
	u.done(w, r, "/account", err, "Two-factor authentication is on. Other sessions were logged out.")
}

func (u *UI) totpDisable(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	err := u.reauth(r, func() error {
		return u.svc.DisableTOTP(r.Context(), sess, r.PostFormValue("password"), r.PostFormValue("code"))
	})
	u.done(w, r, "/account", err, "Two-factor authentication is off.")
}
