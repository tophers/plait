package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"plait/internal/model"
	"plait/internal/store/db"
)

const (
	SessionLifetime = 12 * time.Hour
	SessionIdle     = 2 * time.Hour
	minPasswordLen  = 12
	// maxPasswordLen bounds what anyone, authenticated or not, can make the
	// controller hash.
	maxPasswordLen = 256
)

// argonWait is how long a login waits for a hashing slot before failing with
// ErrBusy; tests may lower it.
var argonWait = 5 * time.Second

// Argon2Params are the argon2id cost parameters; tests may lower them.
var Argon2Params = struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}{Memory: 64 * 1024, Time: 3, Threads: 2}

var (
	ErrBadLogin = errors.New("invalid username, password, or authentication code")
	ErrBusy     = errors.New("too many logins in progress; try again shortly")
)

// argonSlots caps concurrent argon2id computations, each of which allocates
// its full memory cost (64 MiB by default), so a burst of logins cannot
// exhaust the controller's memory.
var argonSlots = make(chan struct{}, 4)

func argonKey(ctx context.Context, password string, salt []byte, t, memory uint32, threads uint8, n uint32) ([]byte, error) {
	timer := time.NewTimer(argonWait)
	defer timer.Stop()
	select {
	case argonSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrBusy
	}
	defer func() { <-argonSlots }()
	return argon2.IDKey([]byte(password), salt, t, memory, threads, n), nil
}

func hashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := Argon2Params
	key, err := argonKey(ctx, password, salt, p.Time, p.Memory, p.Threads, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, nil
	}
	var version int
	var memory, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, nil
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &t, &threads); err != nil {
		return false, nil
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false, nil
	}
	got, err := argonKey(ctx, password, salt, t, memory, threads, uint32(len(want)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash equalizes login timing for unknown usernames.
var dummyHash, _ = hashPassword(context.Background(), "plait-dummy-password")

func validatePassword(pw string) error {
	if len(pw) < minPasswordLen {
		return &model.ValidationError{Msg: fmt.Sprintf("password must be at least %d characters", minPasswordLen)}
	}
	if len(pw) > maxPasswordLen {
		return &model.ValidationError{Msg: fmt.Sprintf("password must be at most %d bytes", maxPasswordLen)}
	}
	return nil
}

// CreateAdmin adds an administrator. v1 has a single administrator role.
func (s *Service) CreateAdmin(ctx context.Context, username, password string) error {
	if err := model.ValidateName(username); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(ctx, password)
	if err != nil {
		return err
	}
	id := uuid.NewString()
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if err := q.CreateAdmin(ctx, db.CreateAdminParams{ID: id, Username: username, PasswordHash: hash}); err != nil {
			return uniqueAsValidation(err, "administrator already exists")
		}
		return s.audit(ctx, q, &auditEvent{Action: "admin.create", TargetType: "admin", TargetID: id, Details: map[string]any{"username": username}})
	})
}

// SetAdminPassword changes a password and ends that administrator's sessions.
func (s *Service) SetAdminPassword(ctx context.Context, username, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(ctx, password)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		a, err := q.GetAdminByUsername(ctx, username)
		if err != nil {
			return notFound("administrator", username, err)
		}
		if err := q.UpdateAdminPassword(ctx, db.UpdateAdminPasswordParams{PasswordHash: hash, ID: a.ID}); err != nil {
			return err
		}
		if err := q.DeleteAdminSessions(ctx, a.ID); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "admin.password", TargetType: "admin", TargetID: a.ID})
	})
}

func (s *Service) AdminCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		n, err = q.CountAdmins(ctx)
		return err
	})
	return n, err
}

// Session is an authenticated administrator session.
type Session struct {
	Username  string
	CSRFToken string
	ExpiresAt time.Time
	idHash    []byte
}

func sessionHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// checkPassword returns the administrator if password is theirs, and
// ErrBadLogin otherwise, spending the same hashing work on unknown usernames.
func (s *Service) checkPassword(ctx context.Context, username, password string) (db.Admin, error) {
	var admin db.Admin
	if len(password) > maxPasswordLen {
		return admin, ErrBadLogin
	}
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		admin, err = q.GetAdminByUsername(ctx, username)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := verifyPassword(ctx, dummyHash, password); err != nil {
			return admin, err
		}
		return admin, ErrBadLogin
	}
	if err != nil {
		return admin, err
	}
	ok, err := verifyPassword(ctx, admin.PasswordHash, password)
	if err != nil {
		return admin, err
	}
	if !ok {
		return admin, ErrBadLogin
	}
	return admin, nil
}

// Login verifies credentials and creates a session. code is required only
// for administrators with TOTP enabled; each code is accepted once. It
// returns the cookie secret; only its hash is stored.
func (s *Service) Login(ctx context.Context, username, password, code string) (string, *Session, error) {
	admin, err := s.checkPassword(ctx, username, password)
	if err != nil {
		return "", nil, err
	}
	var step int64
	if admin.TotpEnabledAt.Valid {
		if step, err = s.matchTOTP(admin, code); err != nil {
			return "", nil, err
		}
	}
	secret, err := randomString(32)
	if err != nil {
		return "", nil, err
	}
	csrf, err := randomString(32)
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	sess := &Session{Username: admin.Username, CSRFToken: csrf, ExpiresAt: now.Add(SessionLifetime), idHash: sessionHash(secret)}
	err = s.store.Tx(WithActor(ctx, "admin:"+admin.Username), func(_ *sql.Tx, q *db.Queries) error {
		if step > 0 {
			if err := advanceTOTP(ctx, q, admin.ID, step); err != nil {
				return err
			}
		}
		if err := q.DeleteExpiredSessions(ctx, fmtTime(now)); err != nil {
			return err
		}
		if err := q.CreateSession(ctx, db.CreateSessionParams{
			IDHash: sess.idHash, AdminID: admin.ID, CsrfToken: csrf, ExpiresAt: fmtTime(sess.ExpiresAt), LastSeenAt: fmtTime(now),
		}); err != nil {
			return err
		}
		return s.audit(WithActor(ctx, "admin:"+admin.Username), q, &auditEvent{Action: "admin.login", TargetType: "admin", TargetID: admin.ID})
	})
	if err != nil {
		return "", nil, err
	}
	return secret, sess, nil
}

// Session resolves a cookie secret, enforcing absolute and idle expiry.
func (s *Service) Session(ctx context.Context, secret string) (*Session, error) {
	if secret == "" {
		return nil, ErrUnauthenticated
	}
	h := sessionHash(secret)
	var row db.GetSessionRow
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		var err error
		row, err = q.GetSession(ctx, h)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	expires, lastSeen := parseTime(row.ExpiresAt), parseTime(row.LastSeenAt)
	if !now.Before(expires) || now.Sub(lastSeen) > SessionIdle {
		s.Logout(ctx, secret)
		return nil, ErrUnauthenticated
	}
	if now.Sub(lastSeen) > time.Minute {
		s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
			return q.TouchSession(ctx, db.TouchSessionParams{LastSeenAt: fmtTime(now), IDHash: h})
		})
	}
	return &Session{Username: row.Username, CSRFToken: row.CsrfToken, ExpiresAt: expires, idHash: h}, nil
}

func (s *Service) Logout(ctx context.Context, secret string) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		return q.DeleteSession(ctx, sessionHash(secret))
	})
}
