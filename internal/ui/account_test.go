package ui

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// totpCode is an independent RFC 6238 implementation for tests.
func totpCode(t *testing.T, b32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

var setupSecret = regexp.MustCompile(`<code class="secret">([A-Z2-7]+)</code>`)

func TestTOTPSetupAndLogin(t *testing.T) {
	e := newEnv(t)
	now := time.Unix(1_800_000_000, 0)
	e.svc.SetClock(func() time.Time { return now })
	e.login()

	if _, body := e.get("/account"); !strings.Contains(body, "Set up two-factor authentication") {
		t.Fatal("account page does not offer setup")
	}
	e.form("/account/totp/begin", url.Values{"password": {"wrong password"}})
	if _, body := e.get("/account"); !strings.Contains(body, "incorrect password or authentication code") {
		t.Fatal("wrong password not reported")
	}
	resp, body := e.post("/account/totp/begin", url.Values{"password": {password}, "csrf_token": {e.csrf}})
	m := setupSecret.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil || !strings.Contains(body, `data-otpauth="otpauth://totp/Plait:admin?`) {
		t.Fatalf("setup page: %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("setup page cacheable")
	}
	secret := m[1]
	if _, body := e.get("/account"); strings.Contains(body, secret) {
		t.Fatal("secret shown again on GET")
	}
	e.form("/account/totp/confirm", url.Values{"code": {totpCode(t, secret, now)}})
	if _, body := e.get("/account"); !strings.Contains(body, "Turn off two-factor authentication") {
		t.Fatal("TOTP not on after confirming")
	}

	tryLogin := func(code string) int {
		resp, _ := e.post("/login", url.Values{"username": {"admin"}, "password": {password}, "code": {code}})
		return resp.StatusCode
	}
	if s := tryLogin(""); s != http.StatusUnauthorized {
		t.Fatalf("login without code: %d", s)
	}
	if s := tryLogin(totpCode(t, secret, now)); s != http.StatusUnauthorized {
		t.Fatalf("login reusing the confirming code: %d", s)
	}
	now = now.Add(30 * time.Second)
	if s := tryLogin(totpCode(t, secret, now)); s != http.StatusSeeOther {
		t.Fatalf("login with code: %d", s)
	}
	e.login2(totpCode(t, secret, now.Add(30*time.Second)))
	now = now.Add(60 * time.Second)

	// Password re-checks share the login limiter.
	for range 10 {
		e.form("/account/totp/disable", url.Values{"password": {"wrong password"}, "code": {totpCode(t, secret, now)}})
	}
	e.form("/account/totp/disable", url.Values{"password": {password}, "code": {totpCode(t, secret, now)}})
	if _, body := e.get("/account"); !strings.Contains(body, "too many failed attempts") || !strings.Contains(body, "Turn off two-factor") {
		t.Fatal("disable not throttled after repeated wrong passwords")
	}
}

// login2 logs in with a TOTP code and refreshes the CSRF token.
func (e *env) login2(code string) {
	e.t.Helper()
	resp, _ := e.post("/login", url.Values{"username": {"admin"}, "password": {password}, "code": {code}, "next": {"/"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("login with code: %d", resp.StatusCode)
	}
	_, body := e.get("/")
	e.csrf = csrfMeta.FindStringSubmatch(body)[1]
}

func TestTOTPDisable(t *testing.T) {
	e := newEnv(t)
	now := time.Unix(1_800_000_000, 0)
	e.svc.SetClock(func() time.Time { return now })
	e.login()
	_, body := e.post("/account/totp/begin", url.Values{"password": {password}, "csrf_token": {e.csrf}})
	secret := setupSecret.FindStringSubmatch(body)[1]
	e.form("/account/totp/confirm", url.Values{"code": {totpCode(t, secret, now)}})
	now = now.Add(30 * time.Second)
	e.form("/account/totp/disable", url.Values{"password": {password}, "code": {totpCode(t, secret, now)}})
	if _, body := e.get("/account"); !strings.Contains(body, "Two-factor authentication is off.") {
		t.Fatal("disable not confirmed")
	}
	if resp, _ := e.post("/login", url.Values{"username": {"admin"}, "password": {password}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login after disabling: %d", resp.StatusCode)
	}
}
