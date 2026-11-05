// Package store owns the SQLite database: connection setup, migrations,
// immediate write transactions with bounded retry, and loading stored intent
// into a model.State.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"plait/internal/store/db"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps a pooled SQLite handle. Every pooled connection runs the
// pragmas in the DSN when opened, and non-read-only transactions begin with
// BEGIN IMMEDIATE so read-then-write mutations never need a lock upgrade.
type Store struct {
	DB *sql.DB
}

const maxTxAttempts = 8

// Open opens (creating if needed) the database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()

	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(8)
	s := &Store{DB: sqldb}
	if err := s.verifyPragmas(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// verifyPragmas confirms the connection settings actually took effect.
func (s *Store) verifyPragmas(ctx context.Context) error {
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var mode string
	var fk, busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		return err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "wal") || fk != 1 || busy != 5000 {
		return fmt.Errorf("sqlite pragmas not applied: journal_mode=%s foreign_keys=%d busy_timeout=%d", mode, fk, busy)
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = s.Tx(ctx, func(tx *sql.Tx, _ *db.Queries) error {
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version = ?", version).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("migration %s: %w", version, err)
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Tx runs fn in a BEGIN IMMEDIATE transaction on a single connection,
// restarting the whole transaction on lock contention a bounded number of
// times. fn must be safe to re-run.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx, *db.Queries) error) error {
	var err error
	for attempt := 1; attempt <= maxTxAttempts; attempt++ {
		err = s.txOnce(ctx, fn)
		if err == nil || !IsBusy(err) {
			return err
		}
		backoff := time.Duration(attempt*attempt)*10*time.Millisecond + rand.N(10*time.Millisecond)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("database busy after %d attempts: %w", maxTxAttempts, err)
}

func (s *Store) txOnce(ctx context.Context, fn func(*sql.Tx, *db.Queries) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx, db.New(tx)); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ReadTx runs fn in a deferred, read-only transaction for a consistent view.
func (s *Store) ReadTx(ctx context.Context, fn func(*db.Queries) error) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(db.New(tx))
}

// IsBusy reports whether err is retryable SQLite lock contention.
func IsBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return true
		}
	}
	return false
}

// IsUniqueViolation reports whether err is a UNIQUE or PRIMARY KEY conflict.
func IsUniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		c := se.Code()
		return c == sqlite3.SQLITE_CONSTRAINT_UNIQUE || c == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}
