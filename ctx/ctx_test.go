package ctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/uuid"
)

// Test for GetDefinition
func TestGetDefinition(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		APIID: uuid.New(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	assert.Nil(t, ctx.GetDefinition(req))

	ctx.SetDefinition(req, apiDef)
	cloned := ctx.GetDefinition(req)

	assert.Equal(t, apiDef, cloned)
}

// Test for GetOASDefinition
func TestGetOASDefinition(t *testing.T) {
	oasDef := &oas.OAS{}
	oasDef.Info = &openapi3.Info{
		Title:   uuid.New(),
		Version: "1",
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	assert.Nil(t, ctx.GetOASDefinition(req))

	ctx.SetOASDefinition(req, oasDef)
	cloned := ctx.GetOASDefinition(req)

	assert.Equal(t, oasDef, cloned)
}

// Benchmark for GetDefinition
func BenchmarkGetDefinition(b *testing.B) {
	apiDef := &apidef.APIDefinition{
		APIID: uuid.New(),
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	ctx.SetDefinition(req, apiDef)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := ctx.GetDefinition(req)
		assert.Equal(b, apiDef, cloned)
	}
}

// Benchmark for GetOASDefinition
func BenchmarkGetOASDefinition(b *testing.B) {
	oasDef := &oas.OAS{}
	oasDef.Info = &openapi3.Info{
		Title:   uuid.New(),
		Version: "1",
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	ctx.SetOASDefinition(req, oasDef)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cloned := ctx.GetOASDefinition(req)
		assert.Equal(b, oasDef, cloned)
	}
}
