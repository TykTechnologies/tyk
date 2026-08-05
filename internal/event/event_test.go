package event

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventToString(t *testing.T) {
	t.Parallel()

	t.Run("Event with description", func(t *testing.T) {
		t.Parallel()

		s := String(RateLimitSmoothingUp)
		assert.NotEmpty(t, s)
		assert.Contains(t, s, " ")
	})

	t.Run("Event without description", func(t *testing.T) {
		t.Parallel()

		s := String(Event("invalid"))
		assert.Equal(t, "invalid", s)
	})
}

// TestOAuth2ExchangeEventTypes pins the exact wire strings of the
// token-exchange audit events. These are a cross-repo contract: the dashboard
// audit-event consumer keys off these literal type names, so they must not
// drift. The exchange surface carries exactly two types — a no-matching-provider
// outcome rides OAuth2ExchangeFailed via the oauth2_exchange_outcome meta field, not a
// distinct event type.
func TestOAuth2ExchangeEventTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Event("OAuth2ExchangeSucceeded"), OAuth2ExchangeSucceeded)
	assert.Equal(t, Event("OAuth2ExchangeFailed"), OAuth2ExchangeFailed)
}

func TestAddEventToRequest(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	assert.NoError(t, err)

	// Test adding events to the request context
	Add(req, TokenDeleted)
	Add(req, RateLimitExceeded)

	// Get events from request context
	events := Get(req.Context())

	// Expect the two events we added
	assert.Len(t, events, 2)
	assert.Contains(t, events, TokenDeleted)
	assert.Contains(t, events, RateLimitExceeded)
}
