package event

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-082, SW-REQ-004 [boundary]
// SYS-REQ-082:nominal:nominal
// SYS-REQ-082:boundary:nominal
// SYS-REQ-082:determinism:nominal
// SW-REQ-004:nominal:nominal
// SW-REQ-004:boundary:nominal
// SW-REQ-004:determinism:nominal
// MCDC SYS-REQ-082: event_metadata_exchange_requested=T, event_metadata_result_preserved=T => TRUE
// MCDC SW-REQ-004: event_operation_requested=T, event_operation_result_returned=T => TRUE
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

// Verifies: SYS-REQ-082, SW-REQ-004
func TestAddEventToRequest(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	require.NoError(t, err)

	assert.Nil(t, Get(context.Background()))

	ctx := Set(req.Context(), []Event{TokenCreated})
	assert.Equal(t, []Event{TokenCreated}, Get(ctx))

	// Test adding events to the request context
	Add(req, TokenDeleted)
	Add(req, RateLimitExceeded)

	// Get events from request context
	events := Get(req.Context())

	// Expect the two events we added
	assert.Equal(t, []Event{TokenDeleted, RateLimitExceeded}, events)
}

// Verifies: SYS-REQ-082, SW-REQ-004 [boundary]
// SYS-REQ-082:encoding_safety:nominal
// SW-REQ-004:encoding_safety:nominal
func TestEncodeRequestToEvent(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequestWithContext(context.Background(), "POST", "http://example.com/events", strings.NewReader("payload"))
	require.NoError(t, err)
	req.Header.Set("X-Test", "event")

	encoded := EncodeRequestToEvent(req)
	require.NotEmpty(t, encoded)

	wire, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Contains(t, string(wire), "POST /events HTTP/1.1")
	assert.Contains(t, string(wire), "X-Test: event")
	assert.Contains(t, string(wire), "payload")

	assert.Empty(t, EncodeRequestToEvent(&http.Request{}))
}
