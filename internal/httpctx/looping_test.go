package httpctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// Verifies: STK-REQ-020, SYS-REQ-108, SW-REQ-028
// STK-REQ-020:nominal:nominal
// SYS-REQ-108:nominal:nominal
// SW-REQ-028:nominal:nominal
func TestSetSelfLooping(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.False(t, httpctx.IsSelfLooping(req))
	httpctx.SetSelfLooping(req, true)
	assert.True(t, httpctx.IsSelfLooping(req))
	httpctx.SetSelfLooping(req, false)
	assert.False(t, httpctx.IsSelfLooping(req))
}
