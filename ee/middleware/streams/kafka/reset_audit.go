package kafka

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type resetAuditActorContextKey struct{}

// WithResetAuditActorHash attaches a server-derived credential principal to a
// reset request. Invalid or unbounded values are ignored; HTTP callers have no
// direct field or header that is passed to this helper.
func WithResetAuditActorHash(ctx context.Context, actorHash string) context.Context {
	decoded, err := hex.DecodeString(actorHash)
	if err != nil || len(decoded) != 32 || actorHash != strings.ToLower(actorHash) {
		return ctx
	}
	return context.WithValue(ctx, resetAuditActorContextKey{}, actorHash)
}

func resetAuditActorHash(ctx context.Context) string {
	if ctx != nil {
		if actor, ok := ctx.Value(resetAuditActorContextKey{}).(string); ok {
			return actor
		}
	}
	return hashStatusIdentity("gateway-control-plane")
}

// ResetAuditEvent is the durable, redacted record required for every reset
// transition. Consumer-group and actor values are hashed by the caller; raw
// credentials, acknowledgement tokens and broker addresses have no fields in
// this schema and therefore cannot be serialized accidentally.
type ResetAuditEvent struct {
	Time              time.Time          `json:"time"`
	APIID             string             `json:"api_id"`
	StreamID          string             `json:"stream_id"`
	ComponentID       string             `json:"component_id"`
	ConsumerGroupHash string             `json:"consumer_group_hash"`
	ActorHash         string             `json:"actor_hash"`
	CorrelationID     string             `json:"correlation_id"`
	Reason            string             `json:"reason"`
	PlanID            string             `json:"plan_id"`
	ExecutionID       string             `json:"execution_id,omitempty"`
	Outcome           string             `json:"outcome"`
	Targets           []ResetTargetState `json:"targets,omitempty"`
}

func (e ResetAuditEvent) Validate() error {
	if e.Time.IsZero() || strings.TrimSpace(e.APIID) == "" || strings.TrimSpace(e.StreamID) == "" || strings.TrimSpace(e.ComponentID) == "" || strings.TrimSpace(e.ConsumerGroupHash) == "" || strings.TrimSpace(e.ActorHash) == "" || strings.TrimSpace(e.CorrelationID) == "" || strings.TrimSpace(e.PlanID) == "" || strings.TrimSpace(e.Outcome) == "" {
		return errors.New("incomplete Kafka reset audit event")
	}
	return nil
}

// DurableResetAuditSink returns nil only after the event is durably accepted.
// Reset execution must fail closed when a mandatory audit write fails.
type DurableResetAuditSink interface {
	WriteResetAudit(context.Context, ResetAuditEvent) error
}
