package oauth2common

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyExchangeOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want OutcomeKind
	}{
		{"nil is ok", nil, OutcomeOK},
		{"no matching provider", &NoMatchingProviderError{Iss: "https://idp.example"}, OutcomeNoMatchingProvider},
		{"misconfig", &MisconfigError{Reason: "audience unresolvable"}, OutcomeMisconfig},
		{"idp rejection", &ExchangeFailedError{Status: 400, IdpError: "invalid_grant"}, OutcomeIdPError},
		{"actor not authorized", &ActorNotAuthorizedError{Reason: "may_act mismatch"}, OutcomeActorNotAuthorized},
		{"generic error treated as idp_error", errors.New("dial tcp: connection refused"), OutcomeIdPError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, ClassifyExchangeOutcome(tt.err))
		})
	}
}

// TestClassifyExchangeOutcome_Wrapped pins that the classifier sees through
// a wrapped typed error (the exchange path may annotate errors with %w).
func TestClassifyExchangeOutcome_Wrapped(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("exchange step: %w", &NoMatchingProviderError{Iss: "x"})
	assert.Equal(t, OutcomeNoMatchingProvider, ClassifyExchangeOutcome(wrapped))
}

// TestOutcomeKind_WireValues pins the exact label strings — they are the join
// key across the metric label, the structured log line, and the audit event,
// and are asserted by downstream consumers, so they must not drift.
func TestOutcomeKind_WireValues(t *testing.T) {
	t.Parallel()

	assert.Equal(t, OutcomeKind("ok"), OutcomeOK)
	assert.Equal(t, OutcomeKind("idp_error"), OutcomeIdPError)
	assert.Equal(t, OutcomeKind("misconfig"), OutcomeMisconfig)
	assert.Equal(t, OutcomeKind("no_matching_provider"), OutcomeNoMatchingProvider)
	assert.Equal(t, OutcomeKind("actor_not_authorized"), OutcomeActorNotAuthorized)
}
