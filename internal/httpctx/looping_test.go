package httpctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

func TestSetSelfLooping(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.False(t, httpctx.IsSelfLooping(req))
	httpctx.SetSelfLooping(req, true)
	assert.True(t, httpctx.IsSelfLooping(req))
	httpctx.SetSelfLooping(req, false)
	assert.False(t, httpctx.IsSelfLooping(req))
}
