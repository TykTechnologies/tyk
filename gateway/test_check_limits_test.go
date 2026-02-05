package gateway

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

func TestCtxCheckLimits_ExplicitFlag(t *testing.T) {
	// Test that explicit check_limits=true flag is respected even for self-loops
	r := httptest.NewRequest("GET", "/", nil)

	// Simulate self-looping (like internal redirects do)
	httpctx.SetSelfLooping(r, true)

	// Without explicit flag, should skip limits for self-loops
	assert.False(t, ctxCheckLimits(r), "Should skip limits for self-loops by default")

	// With explicit check_limits=true, should apply limits
	ctxSetCheckLoopLimits(r, true)
	assert.True(t, ctxCheckLimits(r), "Should apply limits when check_limits=true")

	// With explicit check_limits=false, should skip limits
	ctxSetCheckLoopLimits(r, false)
	assert.False(t, ctxCheckLimits(r), "Should skip limits when check_limits=false")
}
