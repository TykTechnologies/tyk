package ctx_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
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

// Test for GetErrorClassification
func TestErrorClassificationContext(t *testing.T) {
	t.Run("get returns nil when not set", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		assert.Nil(t, ctx.GetErrorClassification(req))
	})

	t.Run("get returns set value", func(t *testing.T) {
		errClass := errors.NewErrorClassification(errors.UCF, "connection_refused").
			WithSource("ReverseProxy").
			WithTarget("api.backend.com:443")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		ctx.SetErrorClassification(req, errClass)
		result := ctx.GetErrorClassification(req)

		assert.Equal(t, errClass, result)
		assert.Equal(t, errors.UCF, result.Flag)
		assert.Equal(t, "connection_refused", result.Details)
		assert.Equal(t, "ReverseProxy", result.Source)
		assert.Equal(t, "api.backend.com:443", result.Target)
	})

	t.Run("TLS error with cert info", func(t *testing.T) {
		expiry := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		errClass := errors.NewErrorClassification(errors.TLE, "tls_certificate_expired").
			WithSource("ReverseProxy").
			WithTarget("api.backend.com:443").
			WithTLSInfo(expiry, "CN=api.backend.com")

		req := httptest.NewRequest("GET", "http://example.com", nil)
		ctx.SetErrorClassification(req, errClass)
		result := ctx.GetErrorClassification(req)

		assert.Equal(t, errors.TLE, result.Flag)
		assert.Equal(t, expiry, result.TLSCertExpiry)
		assert.Equal(t, "CN=api.backend.com", result.TLSCertSubject)
	})
}

func TestErrorClassificationContext_NilSafe(t *testing.T) {
	t.Run("set nil does not panic", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		assert.NotPanics(t, func() {
			ctx.SetErrorClassification(req, nil)
		})
		// After setting nil, get should return nil
		assert.Nil(t, ctx.GetErrorClassification(req))
	})
}
