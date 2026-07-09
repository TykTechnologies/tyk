package oauth2common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyExchangeOutcome_StepUpRequired(t *testing.T) {
	err := &StepUpRequiredError{Claims: `{"access_token":{}}`}
	assert.Equal(t, OutcomeStepUpRequired, ClassifyExchangeOutcome(err))

	wrapped := fmt.Errorf("wrapped: %w", err)
	assert.Equal(t, OutcomeStepUpRequired, ClassifyExchangeOutcome(wrapped))
}

func TestDecodeClaimsChallenge(t *testing.T) {
	t.Run("claims and authorization_uri decoded", func(t *testing.T) {
		body := []byte(`{"error":"interaction_required","claims":"{\"access_token\":{}}","authorization_uri":"https://idp/authorize"}`)
		claims, authURI := DecodeClaimsChallenge(body)
		assert.Equal(t, `{"access_token":{}}`, claims)
		assert.Equal(t, "https://idp/authorize", authURI)
	})

	t.Run("absent fields decode to empty strings", func(t *testing.T) {
		claims, authURI := DecodeClaimsChallenge([]byte(`{"error":"interaction_required"}`))
		assert.Empty(t, claims)
		assert.Empty(t, authURI)
	})
}
