package httpctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
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

func TestCallingSpec_RoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	spec := &apidef.APIDefinition{APIID: "api-1"}

	req = httpctx.SetCallingSpec(req, spec)
	got := httpctx.GetCallingSpec(req)

	assert.Same(t, spec, got)
}

func TestCallingSpec_UnsetReturnsNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.Nil(t, httpctx.GetCallingSpec(req))
}

func TestCallingSpec_OverwriteNotNested(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	first := &apidef.APIDefinition{APIID: "api-1"}
	second := &apidef.APIDefinition{APIID: "api-2"}

	req = httpctx.SetCallingSpec(req, first)
	req = httpctx.SetCallingSpec(req, second)

	got := httpctx.GetCallingSpec(req)
	assert.Same(t, second, got, "second SetCallingSpec must overwrite the first (transitive-trust guard)")
	assert.NotSame(t, first, got)
}

func TestSkipAuth_RoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req = httpctx.SetSkipAuth(req)
	assert.True(t, httpctx.IsAuthSkipped(req))
}

func TestSkipAuth_UnsetReturnsFalse(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.False(t, httpctx.IsAuthSkipped(req))
}

func TestCallingSpecAndSkipAuth_Independent(t *testing.T) {
	// Setting calling spec must not implicitly skip auth.
	req1 := httptest.NewRequest("GET", "/", nil)
	spec := &apidef.APIDefinition{APIID: "api-1"}
	req1 = httpctx.SetCallingSpec(req1, spec)
	assert.False(t, httpctx.IsAuthSkipped(req1))
	assert.Same(t, spec, httpctx.GetCallingSpec(req1))

	// Setting skip-auth must not populate a calling spec.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2 = httpctx.SetSkipAuth(req2)
	assert.Nil(t, httpctx.GetCallingSpec(req2))
	assert.True(t, httpctx.IsAuthSkipped(req2))
}
