package controller

import (
	"context"
	"encoding/json"
	"math"

	"plait/internal/store/db"
)

type actorKey struct{}

// WithActor attributes mutations made with ctx to actor, e.g.
// "admin:alice", "agent:<site id>", or "local:plaitctl".
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorFrom(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey{}).(string); ok && a != "" {
		return a
	}
	return "unknown"
}

// auditEvent describes an administrative change. Details must never contain
// private keys, PSKs, tokens, or full profiles.
type auditEvent struct {
	Action     string
	TargetType string
	TargetID   string
	Details    any
}

func (s *Service) audit(ctx context.Context, q *db.Queries, ev *auditEvent) error {
	if ev == nil {
		return nil
	}
	details := []byte("{}")
	if ev.Details != nil {
		b, err := json.Marshal(ev.Details)
		if err != nil {
			return err
		}
		details = b
	}
	return q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Actor: actorFrom(ctx), Action: ev.Action, TargetType: ev.TargetType, TargetID: ev.TargetID, Details: string(details),
	})
}

// AuditEvent is one recorded administrative change.
type AuditEvent struct {
	ID         int64           `json:"id"`
	At         string          `json:"at"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Details    json.RawMessage `json:"details"`
}

// AuditLog returns up to limit events older than before (0: newest).
func (s *Service) AuditLog(ctx context.Context, before int64, limit int) ([]AuditEvent, error) {
	if before <= 0 {
		before = math.MaxInt64
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []AuditEvent
	err := s.store.ReadTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListAuditEvents(ctx, db.ListAuditEventsParams{ID: before, Limit: int64(limit)})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, AuditEvent{ID: r.ID, At: r.At, Actor: r.Actor, Action: r.Action,
				TargetType: r.TargetType, TargetID: r.TargetID, Details: json.RawMessage(r.Details)})
		}
		return nil
	})
	return out, err
}
