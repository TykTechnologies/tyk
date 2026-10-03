package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResetAuditActorContextIsFixedAndRequestScoped(t *testing.T) {
	actor := sha256.Sum256([]byte("credential-a"))
	hash := fmt.Sprintf("%x", actor[:])
	ctx := WithResetAuditActorHash(context.Background(), hash)
	require.Equal(t, hash, resetAuditActorHash(ctx))
	require.NotEqual(t, hash, resetAuditActorHash(context.Background()))
	require.NotEqual(t, "credential-a", resetAuditActorHash(ctx))
	require.Equal(t, resetAuditActorHash(context.Background()), resetAuditActorHash(WithResetAuditActorHash(context.Background(), "not-a-digest")))
}

type recordingResetAuditSink struct {
	events []ResetAuditEvent
	err    error
}

func (s *recordingResetAuditSink) WriteResetAudit(_ context.Context, event ResetAuditEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func TestResetAuditEventSchemaIsRedacted(t *testing.T) {
	event := ResetAuditEvent{Time: time.Now(), APIID: "api", StreamID: "stream", ComponentID: "input", ConsumerGroupHash: "group-hash", ActorHash: "actor-hash", CorrelationID: "correlation", PlanID: "plan", Outcome: "completed"}
	require.NoError(t, event.Validate())
	payload, err := json.Marshal(event)
	require.NoError(t, err)
	for _, forbidden := range []string{"ack_token", "authorization", "password", "seed_broker", "consumer_group\""} {
		require.NotContains(t, strings.ToLower(string(payload)), forbidden)
	}
}

func TestResetAuditEventRequiresBoundedIdentityFields(t *testing.T) {
	require.Error(t, (ResetAuditEvent{}).Validate())
}

func TestResetPlanFailsClosedWhenDurableAuditFails(t *testing.T) {
	controller, _, _, _ := newResetFixture(t)
	controller.auditor = &recordingResetAuditSink{err: errors.New("audit unavailable")}
	controller.requireAudit = true
	controller.auditKey = ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
	offset := int64(25)
	_, err := controller.PlanReset(context.Background(), ResetPlanRequest{ConsumerGroup: "vinci", Reason: "operator replay", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}}})
	require.ErrorContains(t, err, "audit unavailable")
}

func TestResetAuditRecordsRedactedPlanAndOutcome(t *testing.T) {
	controller, _, _, _ := newResetFixture(t)
	sink := &recordingResetAuditSink{}
	controller.auditor, controller.requireAudit = sink, true
	controller.auditKey = ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
	offset := int64(25)
	actor := fmt.Sprintf("%x", sha256.Sum256([]byte("authenticated-credential")))
	ctx := WithResetAuditActorHash(context.Background(), actor)
	plan, err := controller.PlanReset(ctx, ResetPlanRequest{ConsumerGroup: "vinci", Reason: "operator replay", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}}})
	require.NoError(t, err)
	_, err = controller.ExecuteReset(ctx, ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	require.Len(t, sink.events, 2)
	require.Equal(t, "planned", sink.events[0].Outcome)
	require.Equal(t, "completed", sink.events[1].Outcome)
	require.NotEqual(t, "vinci", sink.events[0].ConsumerGroupHash)
	require.Equal(t, actor, sink.events[0].ActorHash)
	require.Equal(t, actor, sink.events[1].ActorHash)
}
