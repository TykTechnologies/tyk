package event

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddEventToRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
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
