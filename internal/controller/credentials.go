package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"plait/internal/model"
	"plait/internal/store/db"
	"plait/internal/wg"
)

// Tokens have the form <prefix>_<selector>_<secret>. The selector locates the
// row; only SHA-256(secret) is stored. Secrets carry 256 bits of randomness.
const (
	enrollmentPrefix = "plaite"
	agentPrefix      = "plaita"
	timeFormat       = "2006-01-02T15:04:05.000Z"

	DefaultEnrollmentTTL     = time.Hour
	DefaultCredentialOverlap = 10 * time.Minute
)

var (
	ErrUnauthenticated = errors.New("invalid or expired credential")
	ErrEnrollment      = errors.New("invalid, expired, or already used enrollment token")
	ErrRotationTooSoon = errors.New("a previous rotation's overlap has not ended; rotate after the old credential expires, or re-enroll the gateway if its new credential was lost")
)

func newToken(prefix string) (token, selector string, hash []byte, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", nil, err
	}
	selector = uuid.NewString()
	enc := base64.RawURLEncoding.EncodeToString(secret)
	sum := sha256.Sum256([]byte(enc))
	return prefix + "_" + selector + "_" + enc, selector, sum[:], nil
}

func parseToken(prefix, token string) (selector string, hash []byte, ok bool) {
	parts := strings.SplitN(token, "_", 3) // the secret itself may contain "_"
	if len(parts) != 3 || parts[0] != prefix || len(parts[2]) != 43 {
		return "", nil, false
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		return "", nil, false
	}
	sum := sha256.Sum256([]byte(parts[2]))
	return parts[1], sum[:], true
}

func fmtTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// CreateEnrollmentToken issues a single-use token that lets a gateway bind its
// public key to siteID. Issuing a token for an already enrolled site
// authorizes a gateway key replacement.
func (s *Service) CreateEnrollmentToken(ctx context.Context, siteID string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 || ttl > 24*time.Hour {
		return "", time.Time{}, &model.ValidationError{Msg: "enrollment token lifetime must be between 1s and 24h"}
	}
	token, selector, hash, err := newToken(enrollmentPrefix)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := s.now().Add(ttl)
	err = s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if _, err := q.GetSite(ctx, siteID); err != nil {
			return notFound("site", siteID, err)
		}
		if err := q.InvalidateSiteEnrollmentTokens(ctx, siteID); err != nil {
			return err
		}
		if err := q.CreateEnrollmentToken(ctx, db.CreateEnrollmentTokenParams{
			ID: selector, SiteID: siteID, TokenHash: hash, ExpiresAt: fmtTime(expires),
		}); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "site.enrollment_token", TargetType: "site", TargetID: siteID,
			Details: map[string]any{"token_id": selector, "expires_at": fmtTime(expires)}})
	})
	return token, expires, err
}

// EnrollSite consumes an enrollment token, binds publicKey to its site, and
// returns a new site credential. Existing credentials for the site are
// revoked because they belonged to the previous gateway identity.
func (s *Service) EnrollSite(ctx context.Context, token string, publicKey wg.Key) (siteID, credential string, err error) {
	selector, hash, ok := parseToken(enrollmentPrefix, token)
	if !ok {
		return "", "", ErrEnrollment
	}
	if publicKey.IsZero() {
		return "", "", &model.ValidationError{Msg: "gateway public key is required"}
	}
	credential, credID, credHash, err := newToken(agentPrefix)
	if err != nil {
		return "", "", err
	}
	ev := &auditEvent{Action: "site.enroll", TargetType: "site"}
	err = s.mutate(WithActor(ctx, "enrollment:"+selector), ev, func(q *db.Queries, before *model.State) error {
		row, err := q.GetEnrollmentToken(ctx, selector)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEnrollment
			}
			return err
		}
		if subtle.ConstantTimeCompare(row.TokenHash, hash) != 1 || row.ConsumedAt.Valid || !s.now().Before(parseTime(row.ExpiresAt)) {
			return ErrEnrollment
		}
		n, err := q.ConsumeEnrollmentToken(ctx, selector)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrEnrollment
		}
		site, ok := before.Site(row.SiteID)
		if !ok {
			return ErrEnrollment
		}
		siteID = site.ID
		ev.TargetID = site.ID
		ev.Details = map[string]any{"public_key": publicKey.String(), "token_id": selector,
			"replaced_key": !site.Pending() && !site.PublicKey.Equal(publicKey)}
		if err := q.SetSitePublicKey(ctx, db.SetSitePublicKeyParams{PublicKey: nullKey(publicKey), ID: site.ID}); err != nil {
			return uniqueAsValidation(err, "public key already in use")
		}
		if err := q.RevokeSiteCredentials(ctx, site.ID); err != nil {
			return err
		}
		return q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: credID, SiteID: site.ID, TokenHash: credHash})
	})
	if err != nil {
		return "", "", err
	}
	return siteID, credential, nil
}

// Agent is an authenticated agent request context.
type Agent struct {
	SiteID       string
	CredentialID string
}

// AuthenticateAgent verifies a bearer credential and returns the site it is
// bound to. The site comes only from the credential, never from the request.
func (s *Service) AuthenticateAgent(ctx context.Context, bearer string) (*Agent, error) {
	selector, hash, ok := parseToken(agentPrefix, bearer)
	if !ok {
		return nil, ErrUnauthenticated
	}
	var row db.AgentCredential
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		row, err = q.GetAgentCredential(ctx, selector)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(row.TokenHash, hash) != 1 || row.RevokedAt.Valid {
		return nil, ErrUnauthenticated
	}
	if row.ExpiresAt.Valid && !s.now().Before(parseTime(row.ExpiresAt.String)) {
		return nil, ErrUnauthenticated
	}
	return &Agent{SiteID: row.SiteID, CredentialID: row.ID}, nil
}

// RotateAgentCredential issues a new credential for the agent's site. Every
// other live credential for the site expires after overlap; until then,
// further rotation is refused.
func (s *Service) RotateAgentCredential(ctx context.Context, a *Agent, overlap time.Duration) (string, error) {
	token, id, hash, err := newToken(agentPrefix)
	if err != nil {
		return "", err
	}
	now := s.now()
	err = s.store.Tx(WithActor(ctx, "agent:"+a.SiteID), func(_ *sql.Tx, q *db.Queries) error {
		// One rotation at a time: while an earlier overlap runs, a holder of
		// any live credential could otherwise churn credentials and keep
		// re-extending the others' expiry.
		pending, err := q.CountExpiringSiteCredentials(ctx, db.CountExpiringSiteCredentialsParams{SiteID: a.SiteID, ExpiresAt: sql.NullString{String: fmtTime(now), Valid: true}})
		if err != nil {
			return err
		}
		if pending > 0 {
			return ErrRotationTooSoon
		}
		if err := q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: id, SiteID: a.SiteID, TokenHash: hash}); err != nil {
			return err
		}
		if err := q.ExpireOtherSiteCredentials(ctx, db.ExpireOtherSiteCredentialsParams{
			ExpiresAt: sql.NullString{String: fmtTime(now.Add(overlap)), Valid: true},
			SiteID:    a.SiteID, ID: id,
			ExpiresAt_2: sql.NullString{String: fmtTime(now.Add(overlap)), Valid: true},
		}); err != nil {
			return err
		}
		return s.audit(WithActor(ctx, "agent:"+a.SiteID), q, &auditEvent{Action: "site.credential_rotate", TargetType: "site",
			TargetID: a.SiteID, Details: map[string]any{"new_credential_id": id, "previous_credential_id": a.CredentialID, "overlap": overlap.String()}})
	})
	return token, err
}

// RevokeSiteCredentials blocks all controller access for a site's agent. It
// does not remove cached peers from an unreachable gateway.
func (s *Service) RevokeSiteCredentials(ctx context.Context, siteID string) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if _, err := q.GetSite(ctx, siteID); err != nil {
			return notFound("site", siteID, err)
		}
		if err := q.RevokeSiteCredentials(ctx, siteID); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "site.credentials_revoke", TargetType: "site", TargetID: siteID})
	})
}

// Credential describes an agent credential without its secret.
type Credential struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Active    bool   `json:"active"`
}

func (s *Service) SiteCredentials(ctx context.Context, siteID string) ([]Credential, error) {
	out := []Credential{}
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListSiteCredentials(ctx, siteID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			active := !r.RevokedAt.Valid && (!r.ExpiresAt.Valid || s.now().Before(parseTime(r.ExpiresAt.String)))
			out = append(out, Credential{ID: r.ID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt.String, RevokedAt: r.RevokedAt.String, Active: active})
		}
		return nil
	})
	return out, err
}
