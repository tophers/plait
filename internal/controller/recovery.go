package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"plait/internal/store/db"
)

const recoverySetting = "recovery_pending"

// Backup writes a consistent copy of the database, including committed WAL
// contents, to dest using VACUUM INTO. The PSK encryption key is not part of
// the database and must be backed up separately.
func (s *Service) Backup(ctx context.Context, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists", dest)
	}
	if _, err := s.store.DB.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return err
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return err
	}
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		return s.audit(ctx, q, &auditEvent{Action: "controller.backup", TargetType: "controller", TargetID: "-"})
	})
}

// BeginRecovery marks a restored database. While set, agents receive no
// desired state, so an older database cannot silently re-enable access
// revoked after the backup. Status reports are still accepted so the
// administrator can see how far ahead each agent is.
func (s *Service) BeginRecovery(ctx context.Context) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		if err := q.SetSetting(ctx, db.SetSettingParams{Key: recoverySetting, Value: fmtTime(s.now())}); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "controller.recovery_begin", TargetType: "controller", TargetID: "-"})
	})
}

func (s *Service) InRecovery(ctx context.Context) (bool, error) {
	var pending bool
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		_, err := q.GetSetting(ctx, recoverySetting)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		pending = err == nil
		return err
	})
	return pending, err
}

// CompleteRecovery advances every site's desired revision beyond anything its
// agent has reported accepting, then resumes distribution. The administrator
// must first re-apply any revocations made after the backup was taken.
func (s *Service) CompleteRecovery(ctx context.Context) error {
	return s.store.Tx(ctx, func(_ *sql.Tx, q *db.Queries) error {
		sites, err := q.ListSites(ctx)
		if err != nil {
			return err
		}
		statuses, err := q.ListSiteStatus(ctx)
		if err != nil {
			return err
		}
		accepted := map[string]int64{}
		for _, st := range statuses {
			accepted[st.SiteID] = st.AcceptedRevision.Int64
		}
		advanced := map[string]int64{}
		for _, site := range sites {
			to := max(site.DesiredRevision, accepted[site.ID]) + 1
			if err := q.AdvanceSiteRevision(ctx, db.AdvanceSiteRevisionParams{Revision: to, ID: site.ID}); err != nil {
				return err
			}
			advanced[site.ID] = to
		}
		if err := q.DeleteSetting(ctx, recoverySetting); err != nil {
			return err
		}
		return s.audit(ctx, q, &auditEvent{Action: "controller.recovery_complete", TargetType: "controller", TargetID: "-",
			Details: map[string]any{"advanced_revisions": advanced}})
	})
}
