package controller

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"plait/internal/model"
)

// RFC 6238 appendix B, SHA-1, truncated to six digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037", 20000000000: "353130",
	} {
		if got := hotp(secret, unix/totpPeriod); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPStepWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	const now = int64(1111111111)
	step := now / totpPeriod
	if got := totpStep(secret, hotp(secret, step), now, 0); got != step {
		t.Fatalf("current code: step %d, want %d", got, step)
	}
	if got := totpStep(secret, hotp(secret, step-1), now, 0); got != step-1 {
		t.Fatal("previous step's code rejected")
	}
	if totpStep(secret, hotp(secret, step-2), now, 0) != 0 || totpStep(secret, hotp(secret, step+2), now, 0) != 0 {
		t.Fatal("code outside the skew window accepted")
	}
	if totpStep(secret, hotp(secret, step), now, step) != 0 {
		t.Fatal("already-used step accepted")
	}
	c := hotp(secret, step)
	if totpStep(secret, c[:3]+" "+c[3:], now, 0) != step {
		t.Fatal("code with a space rejected")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if totpStep(secret, bad, now, 0) != 0 {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTOTPLifecycle(t *testing.T) {
	svc, _ := newService(t, "10.0.0.0/24")
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	svc.SetClock(func() time.Time { return now })
	const pw = "correct horse battery"
	if err := svc.CreateAdmin(ctx, "admin", pw); err != nil {
		t.Fatal(err)
	}
	login := func(code string) (string, *Session, error) { return svc.Login(ctx, "admin", pw, code) }

	if _, err := svc.BeginTOTP(ctx, "admin", "wrong password"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("begin with wrong password: %v", err)
	}
	setup, err := svc.BeginTOTP(ctx, "admin", pw)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(setup.URI)
	if err != nil || u.Scheme != "otpauth" || u.Query().Get("secret") != setup.Secret || u.Query().Get("issuer") != "Plait" {
		t.Fatalf("bad URI %q: %v", setup.URI, err)
	}
	secret, err := totpEncoding.DecodeString(setup.Secret)
	if err != nil || len(secret) != totpSecretLen {
		t.Fatalf("secret: %v", err)
	}
	code := func() string { return hotp(secret, now.Unix()/totpPeriod) }

	// An unconfirmed setup is not enforced.
	_, sess, err := login("")
	if err != nil {
		t.Fatalf("login during unconfirmed setup: %v", err)
	}
	other, _, err := login("")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmTOTP(ctx, sess, "000000"); !model.IsValidation(err) {
		t.Fatalf("confirm with wrong code: %v", err)
	}
	if err := svc.ConfirmTOTP(ctx, sess, code()); err != nil {
		t.Fatal(err)
	}
	if on, _ := svc.TOTPStatus(ctx, "admin"); !on {
		t.Fatal("TOTP not enabled after confirming")
	}
	// Confirming ends other sessions but keeps the confirming one.
	if _, err := svc.Session(ctx, other); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("other session survived: %v", err)
	}
	if _, err := svc.BeginTOTP(ctx, "admin", pw); !model.IsValidation(err) {
		t.Fatalf("begin while enabled: %v", err)
	}

	if _, _, err := login(""); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("login without code: %v", err)
	}
	// The code used to confirm cannot be reused.
	if _, _, err := login(code()); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("confirming code reused: %v", err)
	}
	now = now.Add(totpPeriod * time.Second)
	if _, _, err := login(code()); err != nil {
		t.Fatalf("login with fresh code: %v", err)
	}
	if _, _, err := login(code()); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("login code reused: %v", err)
	}
	if _, _, err := svc.Login(ctx, "admin", "wrong password", code()); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("wrong password with code: %v", err)
	}

	now = now.Add(totpPeriod * time.Second)
	if err := svc.DisableTOTP(ctx, sess, pw, "000000"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("disable with wrong code: %v", err)
	}
	if err := svc.DisableTOTP(ctx, sess, "wrong password", code()); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("disable with wrong password: %v", err)
	}
	if err := svc.DisableTOTP(ctx, sess, pw, code()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := login(""); err != nil {
		t.Fatalf("login after disabling: %v", err)
	}

	// Reset (plaitctl) turns TOTP off without a code and ends sessions.
	setup, _ = svc.BeginTOTP(ctx, "admin", pw)
	secret, _ = totpEncoding.DecodeString(setup.Secret)
	now = now.Add(totpPeriod * time.Second)
	if err := svc.ConfirmTOTP(ctx, sess, code()); err != nil {
		t.Fatal(err)
	}
	cookie, _, err := svc.Login(ctx, "admin", pw, hotp(secret, now.Unix()/totpPeriod+1))
	if err != nil {
		t.Fatalf("login with next step's code: %v", err)
	}
	if err := svc.ResetTOTP(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Session(ctx, cookie); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("session survived reset")
	}
	if _, _, err := login(""); err != nil {
		t.Fatalf("login after reset: %v", err)
	}
	if err := svc.ResetTOTP(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset unknown admin: %v", err)
	}
	if !strings.Contains(setup.URI, "Plait:admin") {
		t.Fatalf("label missing from %q", setup.URI)
	}
}
