package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"

	"plait/internal/model"
	"plait/internal/store/db"
)

// TOTP parameters (RFC 6238). These are the defaults every authenticator app
// supports; the otpauth URI states them anyway.
const (
	totpPeriod     = 30
	totpDigits     = 6
	totpSecretLen  = 20 // 160 bits, the HMAC-SHA1 block-size recommendation
	totpSkewSteps  = 1  // accept one step either side for clock drift
	totpIssuer     = "Plait"
	totpModulus    = 1000000
	totpCodeFormat = "%06d"
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// hotp is RFC 4226's HOTP value for counter.
func hotp(secret []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf(totpCodeFormat, v%totpModulus)
}

// totpStep returns the step whose code equals code, considering steps within
// the skew window that are newer than lastStep, or 0 if none does.
func totpStep(secret []byte, code string, unix, lastStep int64) int64 {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != totpDigits {
		return 0
	}
	now := unix / totpPeriod
	var found int64
	for step := now - totpSkewSteps; step <= now+totpSkewSteps; step++ {
		if step > lastStep && subtle.ConstantTimeCompare([]byte(hotp(secret, step)), []byte(code)) == 1 {
			found = step
		}
	}
	return found
}

// TOTPSetup is an unconfirmed TOTP secret, shown once for the administrator
// to add to an authenticator app.
type TOTPSetup struct {
	Secret string // base32, for manual entry
	URI    string // otpauth:// for a QR code
}

// TOTPStatus reports whether an administrator has TOTP enabled.
func (s *Service) TOTPStatus(ctx context.Context, username string) (enabled bool, err error) {
	err = s.store.ReadTx(ctx, func(q *db.Queries) error {
		a, err := q.GetAdminByUsername(ctx, username)
		if err != nil {
			return notFound("administrator", username, err)
		}
		enabled = a.TotpEnabledAt.Valid
		return nil
	})
	return enabled, err
}

// BeginTOTP stores a new, unconfirmed TOTP secret for an administrator who
// re-enters their password, replacing any earlier unconfirmed one. It is not
// enforced until ConfirmTOTP.
func (s *Service) BeginTOTP(ctx context.Context, username, password string) (*TOTPSetup, error) {
	admin, err := s.checkPassword(ctx, username, password)
	if err != nil {
		return nil, err
	}
	if admin.TotpEnabledAt.Valid {
		return nil, &model.ValidationError{Msg: "two-factor authentication is already enabled; disable it first"}
	}
	secret := make([]byte, totpSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	sealed, err := s.sealer.SealTOTP(admin.ID, secret)
	if err != nil {
		return nil, err
	}
	err = s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		return q.SetAdminTOTPPending(ctx, db.SetAdminTOTPPendingParams{
			TotpSecret: sealed, TotpKeyID: sql.NullString{String: s.sealer.KeyID(), Valid: true}, ID: admin.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	enc := totpEncoding.EncodeToString(secret)
	v := url.Values{"secret": {enc}, "issuer": {totpIssuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(totpDigits)}, "period": {fmt.Sprint(totpPeriod)}}
	label := url.PathEscape(totpIssuer + ":" + admin.Username)
	return &TOTPSetup{Secret: enc, URI: "otpauth://totp/" + label + "?" + v.Encode()}, nil
}

// ConfirmTOTP enables the unconfirmed secret once the administrator proves
// their authenticator produces its codes, and ends their other sessions.
func (s *Service) ConfirmTOTP(ctx context.Context, sess *Session, code string) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		admin, err := q.GetAdminByUsername(ctx, sess.Username)
		if err != nil {
			return notFound("administrator", sess.Username, err)
		}
		if admin.TotpSecret == nil || admin.TotpEnabledAt.Valid {
			return &model.ValidationError{Msg: "no two-factor setup is in progress; start again"}
		}
		secret, err := s.sealer.OpenTOTP(admin.ID, admin.TotpKeyID.String, admin.TotpSecret)
		if err != nil {
			return err
		}
		step := totpStep(secret, code, s.now().Unix(), 0)
		if step == 0 {
			return &model.ValidationError{Msg: "that code is not valid; check that the authenticator's clock is correct and try again"}
		}
		n, err := q.EnableAdminTOTP(ctx, db.EnableAdminTOTPParams{
			TotpEnabledAt: sql.NullString{String: fmtTime(s.now()), Valid: true}, TotpLastStep: step, ID: admin.ID,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return &model.ValidationError{Msg: "no two-factor setup is in progress; start again"}
		}
		if err := q.DeleteOtherAdminSessions(ctx, db.DeleteOtherAdminSessionsParams{AdminID: admin.ID, IDHash: sess.idHash}); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "admin.totp.enable", TargetType: "admin", TargetID: admin.ID})
	})
}

// DisableTOTP turns TOTP off for an administrator who re-enters their
// password and a current code.
func (s *Service) DisableTOTP(ctx context.Context, sess *Session, password, code string) error {
	admin, err := s.checkPassword(ctx, sess.Username, password)
	if err != nil {
		return err
	}
	if !admin.TotpEnabledAt.Valid {
		return &model.ValidationError{Msg: "two-factor authentication is not enabled"}
	}
	step, err := s.matchTOTP(admin, code)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if err := advanceTOTP(ctx, q, admin.ID, step); err != nil {
			return err
		}
		if err := q.ClearAdminTOTP(ctx, admin.ID); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "admin.totp.disable", TargetType: "admin", TargetID: admin.ID})
	})
}

// ResetTOTP turns TOTP off without a code, for an administrator who lost
// their authenticator, and ends their sessions. Only plaitctl, which needs
// access to the controller host, offers it.
func (s *Service) ResetTOTP(ctx context.Context, username string) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		admin, err := q.GetAdminByUsername(ctx, username)
		if err != nil {
			return notFound("administrator", username, err)
		}
		if err := q.ClearAdminTOTP(ctx, admin.ID); err != nil {
			return err
		}
		if err := q.DeleteAdminSessions(ctx, admin.ID); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "admin.totp.reset", TargetType: "admin", TargetID: admin.ID})
	})
}

// matchTOTP returns the step of a valid, unused code for an administrator
// with TOTP enabled, or ErrBadLogin.
func (s *Service) matchTOTP(admin db.Admin, code string) (int64, error) {
	secret, err := s.sealer.OpenTOTP(admin.ID, admin.TotpKeyID.String, admin.TotpSecret)
	if err != nil {
		return 0, err
	}
	step := totpStep(secret, code, s.now().Unix(), admin.TotpLastStep)
	if step == 0 {
		return 0, ErrBadLogin
	}
	return step, nil
}

// advanceTOTP records step as used. It fails with ErrBadLogin if that step
// or a later one was already used, so concurrent logins cannot share a code.
func advanceTOTP(ctx context.Context, q *db.Queries, adminID string, step int64) error {
	n, err := q.AdvanceAdminTOTPStep(ctx, db.AdvanceAdminTOTPStepParams{Step: step, ID: adminID})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrBadLogin
	}
	return nil
}
