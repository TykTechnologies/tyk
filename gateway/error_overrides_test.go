package gateway

import (
	"html/template"
	"net/http/httptest"
	"testing"
	texttemplate "text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
)

// createGateway is a test helper to create a gateway with compiled overrides
func createGateway(overrides apidef.ErrorOverridesMap) *Gateway {
	gw := &Gateway{}
	compiled := CompileErrorOverrides(overrides)
	if compiled != nil {
		gw.SetCompiledErrorOverrides(compiled)
	}
	return gw
}

// TestCompileErrorOverrides tests the compilation of error override rules
func TestCompileErrorOverrides(t *testing.T) {
	t.Run("nil overrides", func(t *testing.T) {
		result := CompileErrorOverrides(nil)
		assert.Nil(t, result)
	})

	t.Run("empty overrides", func(t *testing.T) {
		result := CompileErrorOverrides(apidef.ErrorOverridesMap{})
		assert.Nil(t, result)
	})

	t.Run("exact status code", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Service unavailable",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Contains(t, result.ByExactCode, 500)
		assert.Len(t, result.ByExactCode[500], 1)
		assert.Equal(t, 503, result.ByExactCode[500][0].Response.StatusCode)
	})

	t.Run("pattern status code 4xx", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"4xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Template: "error_client",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Contains(t, result.ByPrefix, 4)
		assert.Len(t, result.ByPrefix[4], 1)
	})

	t.Run("pattern status code 5xx", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Template: "error_server",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Contains(t, result.ByPrefix, 5)
		assert.Len(t, result.ByPrefix[5], 1)
	})

	t.Run("multiple rules for same status code", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database.*timeout",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 504,
						Message:    "Database timeout",
					},
				},
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Generic server error",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Len(t, result.ByExactCode[500], 2)
	})

	t.Run("mixed exact and pattern codes", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Unauthorized"}},
			},
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Internal error"}},
			},
			"4xx": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Client error"}},
			},
			"5xx": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Server error"}},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Len(t, result.ByExactCode, 2)
		assert.Len(t, result.ByPrefix, 2)
		assert.Contains(t, result.ByExactCode, 401)
		assert.Contains(t, result.ByExactCode, 500)
		assert.Contains(t, result.ByPrefix, 4)
		assert.Contains(t, result.ByPrefix, 5)
	})

	t.Run("invalid regex pattern is skipped", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "[invalid(regex",
					},
					Response: apidef.ErrorResponse{
						Message: "Should be skipped",
					},
				},
				{
					Response: apidef.ErrorResponse{
						Message: "Valid rule",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		// Only the valid rule should be compiled
		assert.Len(t, result.ByExactCode[500], 1)
		assert.Equal(t, "Valid rule", result.ByExactCode[500][0].Response.Message)
	})

	t.Run("invalid body template syntax is skipped", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Body: "{{.InvalidSyntax",
					},
				},
				{
					Response: apidef.ErrorResponse{
						Body: `{"error": "valid"}`,
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		// Only the valid rule should be compiled
		assert.Len(t, result.ByExactCode[500], 1)
		assert.Equal(t, `{"error": "valid"}`, result.ByExactCode[500][0].Response.Body)
	})

	t.Run("invalid status code format is skipped", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"abc":  []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "invalid"}}},
			"50x":  []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "invalid pattern"}}},
			"500x": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "too long"}}},
			"500":  []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "valid"}}},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		// Only the valid "500" rule should be compiled
		assert.Len(t, result.ByExactCode, 1)
		assert.Contains(t, result.ByExactCode, 500)
		assert.Empty(t, result.ByPrefix)
	})

	t.Run("body with template variables is compiled", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Body: `{"error": "timeout", "status": {{.StatusCode}}}`,
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		rule := result.ByExactCode[500][0]

		// Check that templates were compiled
		assert.True(t, rule.HasCompiledTemplate())
		assert.NotNil(t, rule.GetCompiledTemplate(false)) // HTML template for JSON
		assert.NotNil(t, rule.GetCompiledTemplate(true))  // Text template for XML
	})

	t.Run("plain body without template variables is not compiled", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Body: `{"error": "Service unavailable"}`,
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		rule := result.ByExactCode[500][0]

		// Plain body should not be compiled as template
		assert.False(t, rule.HasCompiledTemplate())
	})
}

// TestCompileSingleRule tests compilation of individual rules
func TestCompileSingleRule(t *testing.T) {
	t.Run("valid rule with regex", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "database.*timeout",
			},
			Response: apidef.ErrorResponse{
				Message: "Timeout occurred",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.NotNil(t, rule.Match.CompiledPattern)
	})

	t.Run("valid rule with body template", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: "Error {{.StatusCode}}",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("invalid regex pattern", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "[invalid",
			},
		}

		err := compileSingleRule(rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid match pattern")
	})

	t.Run("invalid body template syntax", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: "{{.Invalid",
			},
		}

		err := compileSingleRule(rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid body template")
	})

	t.Run("no match criteria", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Message: "Simple error",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
	})
}

// TestErrorMatcherCompile tests regex compilation in ErrorMatcher
func TestErrorMatcherCompile(t *testing.T) {
	t.Run("valid regex", func(t *testing.T) {
		matcher := &apidef.ErrorMatcher{
			MessagePattern: "database.*error",
		}

		err := matcher.Compile()
		assert.NoError(t, err)
		assert.NotNil(t, matcher.CompiledPattern)
		assert.True(t, matcher.CompiledPattern.MatchString("database connection error"))
	})

	t.Run("invalid regex", func(t *testing.T) {
		matcher := &apidef.ErrorMatcher{
			MessagePattern: "[invalid(regex",
		}

		err := matcher.Compile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("empty pattern", func(t *testing.T) {
		matcher := &apidef.ErrorMatcher{}

		err := matcher.Compile()
		assert.NoError(t, err)
		assert.Nil(t, matcher.CompiledPattern)
	})

	t.Run("already compiled", func(t *testing.T) {
		matcher := &apidef.ErrorMatcher{
			MessagePattern: "test",
		}

		// First compilation
		err := matcher.Compile()
		require.NoError(t, err)
		firstPattern := matcher.CompiledPattern

		// Second compilation should not replace
		err = matcher.Compile()
		assert.NoError(t, err)
		assert.Equal(t, firstPattern, matcher.CompiledPattern)
	})
}

// TestApplyOverride tests the application of error overrides
func TestApplyOverride(t *testing.T) {
	// Helper to create a gateway with compiled overrides
	createGateway := func(overrides apidef.ErrorOverridesMap) *Gateway {
		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		if compiled != nil {
			gw.SetCompiledErrorOverrides(compiled)
		}
		return gw
	}

	createSpec := func(overrides apidef.ErrorOverridesMap) *APISpec {
		spec := &APISpec{}
		compiled := CompileErrorOverrides(overrides)
		if compiled != nil {
			spec.SetCompiledErrorOverrides(compiled)
		}
		return spec
	}

	t.Run("no overrides configured", func(t *testing.T) {
		gw := &Gateway{}
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error message"))
		assert.Nil(t, result)
	})

	t.Run("exact status code match", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Service unavailable",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("internal error"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.StatusCode)
		assert.Equal(t, 500, result.OriginalCode)
		assert.Equal(t, "Service unavailable", result.GetMessageForTemplate())
	})

	t.Run("pattern match 4xx", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"4xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Message: "Client error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 404, []byte("not found"))
		require.NotNil(t, result)
		assert.Equal(t, 404, result.StatusCode) // No override code, keep original
		assert.Equal(t, "Client error", result.GetMessageForTemplate())
	})

	t.Run("pattern match 5xx", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Server error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 502, []byte("bad gateway"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.StatusCode)
		assert.Equal(t, "Server error", result.GetMessageForTemplate())
	})

	t.Run("exact match takes precedence over pattern", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Exact match"}},
			},
			"5xx": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Pattern match"}},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, "Exact match", result.GetMessageForTemplate())
	})

	t.Run("first matching rule wins", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database",
					},
					Response: apidef.ErrorResponse{Message: "Database error"},
				},
				{
					Response: apidef.ErrorResponse{Message: "Generic error"},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Should match first rule with pattern
		result := eo.ApplyOverride(req, 500, []byte("database connection failed"))
		require.NotNil(t, result)
		assert.Equal(t, "Database error", result.GetMessageForTemplate())

		// Should match second rule (generic fallback)
		result = eo.ApplyOverride(req, 500, []byte("random error"))
		require.NotNil(t, result)
		assert.Equal(t, "Generic error", result.GetMessageForTemplate())
	})

	t.Run("message pattern matching", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database.*timeout",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 504,
						Message:    "Database timeout",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Should match
		result := eo.ApplyOverride(req, 500, []byte("database connection timeout"))
		require.NotNil(t, result)
		assert.Equal(t, 504, result.StatusCode)

		// Should not match
		result = eo.ApplyOverride(req, 500, []byte("network error"))
		assert.Nil(t, result)
	})

	t.Run("body field with nested path", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "metadata.error.type",
						BodyValue: "timeout",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 504,
						Message:    "Request timeout",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"metadata": {"error": {"type": "timeout"}}}`)
		result := eo.ApplyOverride(req, 500, body)
		require.NotNil(t, result)
		assert.Equal(t, 504, result.StatusCode)
	})

	t.Run("large body is truncated for matching", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "error at start",
					},
					Response: apidef.ErrorResponse{Message: "Matched"},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Create a large body (> 4KB) with pattern at start
		largeBody := make([]byte, maxBodySizeForMatching+1000)
		copy(largeBody, []byte("error at start"))

		result := eo.ApplyOverride(req, 500, largeBody)
		require.NotNil(t, result)
		assert.Equal(t, "Matched", result.GetMessageForTemplate())
	})

	t.Run("custom headers", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Message: "Rate limited",
						Headers: map[string]string{
							"Retry-After":    "300",
							"X-Rate-Limit":   "100",
							"X-Error-Source": "gateway",
						},
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 429, []byte("too many requests"))
		require.NotNil(t, result)
		assert.Equal(t, "300", result.Headers["Retry-After"])
		assert.Equal(t, "100", result.Headers["X-Rate-Limit"])
		assert.Equal(t, "gateway", result.Headers["X-Error-Source"])
	})

	t.Run("no status code override preserves original", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Message: "Auth failed",
						// Code not specified
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 401, []byte("unauthorized"))
		require.NotNil(t, result)
		assert.Equal(t, 401, result.StatusCode) // Original preserved
	})

	t.Run("non-matching status code", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Server error"}},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// 404 is not configured
		result := eo.ApplyOverride(req, 404, []byte("not found"))
		assert.Nil(t, result)
	})

	t.Run("API-level override takes precedence over gateway-level", func(t *testing.T) {
		gwOverrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Gateway error"}},
			},
		}
		apiOverrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "API error"}},
			},
		}

		gw := createGateway(gwOverrides)
		spec := createSpec(apiOverrides)
		eo := NewErrorOverrides(spec, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, "API error", result.GetMessageForTemplate())
	})

	t.Run("falls back to gateway-level when API-level doesn't match", func(t *testing.T) {
		gwOverrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Gateway error"}},
			},
		}
		apiOverrides := apidef.ErrorOverridesMap{
			"400": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "API error"}},
			},
		}

		gw := createGateway(gwOverrides)
		spec := createSpec(apiOverrides)
		eo := NewErrorOverrides(spec, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, "Gateway error", result.GetMessageForTemplate())
	})

	t.Run("API-level override works without gateway-level overrides", func(t *testing.T) {
		apiOverrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "API error"}},
			},
		}

		gw := &Gateway{}
		spec := createSpec(apiOverrides)
		eo := NewErrorOverrides(spec, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, "API error", result.GetMessageForTemplate())
	})
}

// TestMatchesAdditionalCriteria tests the matching logic for different criteria
func TestMatchesAdditionalCriteria(t *testing.T) {
	eo := &ErrorOverrides{}

	t.Run("no match criteria always matches", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match:    nil,
			Response: apidef.ErrorResponse{Message: "test"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		matches := eo.matchesAdditionalCriteria(req, rule, []byte("any body"))
		assert.True(t, matches)
	})

	t.Run("message pattern match success", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "database",
			},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		matches := eo.matchesAdditionalCriteria(req, rule, []byte("database error occurred"))
		assert.True(t, matches)
	})

	t.Run("message pattern match failure", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "database",
			},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		matches := eo.matchesAdditionalCriteria(req, rule, []byte("network error"))
		assert.False(t, matches)
	})

	t.Run("body field match success", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"error": {"code": "TIMEOUT"}}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.True(t, matches)
	})

	t.Run("body field takes priority over message pattern", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "error",
				BodyField:      "status",
				BodyValue:      "failed",
			},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		// Body field matches - should match even though pattern also matches
		body := []byte(`{"status": "failed", "message": "error occurred"}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.True(t, matches)
	})

	t.Run("fallback to message pattern when body field doesn't match", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "error",
				BodyField:      "status",
				BodyValue:      "failed",
			},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		// Body field doesn't match, but message pattern does
		body := []byte(`{"status": "success", "message": "error occurred"}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.True(t, matches) // Falls back to message pattern
	})
}

// TestFlagMatching tests the flag-based matching functionality
func TestFlagMatching(t *testing.T) {
	eo := &ErrorOverrides{}

	t.Run("flag match success", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag: errors.RLT, // Rate limited
			},
			Response: apidef.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		// Set error classification in context
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.True(t, matches)
	})

	t.Run("flag match failure - different flag", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag: errors.RLT, // Rate limited
			},
			Response: apidef.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		// Set different error classification
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.QEX, "quota_exceeded"))

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.False(t, matches)
	})

	t.Run("flag match failure - no classification in context", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag: errors.RLT,
			},
			Response: apidef.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)
		// No error classification set

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.False(t, matches)
	})

	t.Run("flag takes priority over message pattern", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag:           errors.RLT,
				MessagePattern: "should not be checked",
			},
			Response: apidef.ErrorResponse{Message: "Rate limited"},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		// Set matching flag
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		// Should match on flag, ignoring pattern
		matches := eo.matchesAdditionalCriteria(req, rule, []byte("unrelated body"))
		assert.True(t, matches)
	})

	t.Run("fallback to message pattern when flag doesn't match", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag:           errors.RLT,
				MessagePattern: "timeout",
			},
			Response: apidef.ErrorResponse{Message: "Error"},
		}
		err := rule.Match.Compile()
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/test", nil)

		// Set different flag
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.QEX, "quota_exceeded"))

		// Flag doesn't match, but pattern does
		matches := eo.matchesAdditionalCriteria(req, rule, []byte("connection timeout"))
		assert.True(t, matches)
	})
}

// TestApplyOverrideWithFlag tests ApplyOverride with flag matching
func TestApplyOverrideWithFlag(t *testing.T) {
	createGateway := func(overrides apidef.ErrorOverridesMap) *Gateway {
		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		if compiled != nil {
			gw.SetCompiledErrorOverrides(compiled)
		}
		return gw
	}

	t.Run("flag-based override match", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.RLT,
					},
					Response: apidef.ErrorResponse{
						StatusCode: 429,
						Message:    "Rate limit exceeded - please slow down",
						Headers:    map[string]string{"Retry-After": "60"},
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Set rate limit classification
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		result := eo.ApplyOverride(req, 429, []byte(""))
		require.NotNil(t, result)
		assert.Equal(t, 429, result.StatusCode)
		assert.Equal(t, "Rate limit exceeded - please slow down", result.GetMessageForTemplate())
		assert.Equal(t, "60", result.Headers["Retry-After"])
	})

	t.Run("multiple flag rules - first match wins", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.TKE, // Token expired
					},
					Response: apidef.ErrorResponse{
						Message: "Token expired - please refresh",
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.AMF, // Auth field missing
					},
					Response: apidef.ErrorResponse{
						Message: "Authentication required",
					},
				},
				{
					// Catch-all for other 401 errors
					Response: apidef.ErrorResponse{
						Message: "Unauthorized",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		// Test token expired
		req1 := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req1, errors.NewErrorClassification(errors.TKE, "token_expired"))
		result := eo.ApplyOverride(req1, 401, []byte(""))
		require.NotNil(t, result)
		assert.Equal(t, "Token expired - please refresh", result.GetMessageForTemplate())

		// Test auth field missing
		req2 := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req2, errors.NewErrorClassification(errors.AMF, "auth_field_missing"))
		result = eo.ApplyOverride(req2, 401, []byte(""))
		require.NotNil(t, result)
		assert.Equal(t, "Authentication required", result.GetMessageForTemplate())

		// Test other 401 (no flag match)
		req3 := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req3, errors.NewErrorClassification(errors.TKI, "token_invalid"))
		result = eo.ApplyOverride(req3, 401, []byte(""))
		require.NotNil(t, result)
		assert.Equal(t, "Unauthorized", result.GetMessageForTemplate())
	})

	t.Run("no flag classification falls back to pattern matching", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag:           errors.CBO,         // Circuit breaker
						MessagePattern: "circuit.*breaker", // Fallback pattern
					},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Service temporarily unavailable",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		// No classification set

		// Should fall back to pattern matching
		result := eo.ApplyOverride(req, 500, []byte("circuit breaker is open"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.StatusCode)
	})
}

// TestOverrideResult tests the OverrideResult helper methods
func TestOverrideResult(t *testing.T) {
	t.Run("ShouldWriteDirectly with plain body", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "Service unavailable"}`,
				},
			},
		}

		assert.True(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldWriteDirectly with body template variables", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"error": "Code {{.StatusCode}}"}`,
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{rule: rule}
		assert.False(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldWriteDirectly with file template", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message:  "Error message",
					Template: "error_upstream",
				},
			},
		}

		assert.False(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldUseDefaultTemplate with message only", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message: "Custom error message",
				},
			},
		}

		assert.True(t, result.ShouldUseDefaultTemplate())
	})

	t.Run("ShouldUseDefaultTemplate false with body", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body:    `{"error": "test"}`,
					Message: "Custom error message",
				},
			},
		}

		assert.False(t, result.ShouldUseDefaultTemplate())
	})

	t.Run("GetMessageForTemplate", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message: "Custom error message",
				},
			},
		}

		assert.Equal(t, "Custom error message", result.GetMessageForTemplate())
	})

	t.Run("GetBody", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "test"}`,
				},
			},
		}

		assert.Equal(t, `{"error": "test"}`, result.GetBody())
	})
}

// TestGetInlineTemplate tests inline template compilation
func TestGetInlineTemplate(t *testing.T) {
	t.Run("JSON content - returns HTML template", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"status": {{.StatusCode}}}`,
			},
		}
		err := compileSingleRule(rule)
		require.NoError(t, err)

		ctx := &ErrorResponseContext{IsXML: false}
		result := &OverrideResult{rule: rule}

		tmpl := result.getInlineTemplate(ctx)
		require.NotNil(t, tmpl)

		// Verify it's an html/template
		_, ok := tmpl.(*template.Template)
		assert.True(t, ok)
	})

	t.Run("XML content - returns text template", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `<error><status>{{.StatusCode}}</status></error>`,
			},
		}
		err := compileSingleRule(rule)
		require.NoError(t, err)

		ctx := &ErrorResponseContext{IsXML: true}
		result := &OverrideResult{rule: rule}

		tmpl := result.getInlineTemplate(ctx)
		require.NotNil(t, tmpl)

		// Verify it's a text/template
		_, ok := tmpl.(*texttemplate.Template)
		assert.True(t, ok)
	})

	t.Run("no compiled template - plain body", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: "plain text",
			},
		}

		ctx := &ErrorResponseContext{IsXML: false}
		result := &OverrideResult{rule: rule}

		tmpl := result.getInlineTemplate(ctx)
		assert.Nil(t, tmpl)
	})
}

// TestTemplateCompilationEdgeCases tests edge cases in template compilation
// Note: Templates are only compiled from the Body field, not Message field.
// Message is a semantic value passed to templates as {{.Message}}.
func TestTemplateCompilationEdgeCases(t *testing.T) {
	t.Run("template with only StatusCode", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"code": {{.StatusCode}}}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("template with only Message", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"error": "{{.Message}}"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("template with both variables", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"code": {{.StatusCode}}, "message": "{{.Message}}"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("body with {{ but no template vars", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"json": "with {{ braces }} but not template"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.False(t, rule.HasCompiledTemplate())
	})

	t.Run("empty body", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: "",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.False(t, rule.HasCompiledTemplate())
	})
}

// Tests for new methods

func TestFindMatchingRuleGeneric(t *testing.T) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.AKI},
				Response: apidef.ErrorResponse{Message: "First rule"},
			},
			{
				Response: apidef.ErrorResponse{Message: "Second rule"},
			},
		},
		"5xx": []apidef.ErrorOverride{
			{
				Response: apidef.ErrorResponse{Message: "Pattern rule"},
			},
		},
	}

	gw := createGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	compiled := gw.GetCompiledErrorOverrides()

	t.Run("finds first matching rule in exact code", func(t *testing.T) {
		matchCount := 0
		rule := eo.findMatchingRuleGeneric(compiled, 500, func(_ *apidef.ErrorOverride) bool {
			matchCount++
			return matchCount == 2 // Match second rule
		})

		require.NotNil(t, rule)
		assert.Equal(t, "Second rule", rule.Response.Message)
	})

	t.Run("falls through to pattern match", func(t *testing.T) {
		rule := eo.findMatchingRuleGeneric(compiled, 502, func(_ *apidef.ErrorOverride) bool {
			return true // Match all
		})

		require.NotNil(t, rule)
		assert.Equal(t, "Pattern rule", rule.Response.Message)
	})

	t.Run("returns nil when no match", func(t *testing.T) {
		rule := eo.findMatchingRuleGeneric(compiled, 500, func(_ *apidef.ErrorOverride) bool {
			return false // Match nothing
		})

		assert.Nil(t, rule)
	})

	t.Run("exact code takes precedence over pattern", func(t *testing.T) {
		rule := eo.findMatchingRuleGeneric(compiled, 500, func(_ *apidef.ErrorOverride) bool {
			return true // Match all
		})

		require.NotNil(t, rule)
		assert.Equal(t, "First rule", rule.Response.Message) // From exact match, not pattern
	})
}

func TestApplyUpstreamOverride(t *testing.T) {
	t.Run("returns nil when no overrides configured", func(t *testing.T) {
		gw := createGateway(apidef.ErrorOverridesMap{})
		eo := NewErrorOverrides(&APISpec{}, gw)

		readBodyCalled := false
		result := eo.ApplyUpstreamOverride(500, func() []byte {
			readBodyCalled = true
			return []byte("error")
		})

		assert.Nil(t, result)
		assert.False(t, readBodyCalled, "readBody should not be called when no overrides")
	})

	t.Run("matches exact status code", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"503": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 500,
						Message:    "Upstream unavailable",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(503, func() []byte {
			return []byte("")
		})

		require.NotNil(t, result)
		assert.Equal(t, 500, result.StatusCode)
		assert.Equal(t, 503, result.OriginalCode)
		assert.Equal(t, "Upstream unavailable", result.GetMessageForTemplate())
	})

	t.Run("matches pattern 5xx", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Server error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(502, func() []byte {
			return []byte("")
		})

		require.NotNil(t, result)
		assert.Equal(t, 503, result.StatusCode)
		assert.Equal(t, "Server error", result.GetMessageForTemplate())
	})

	t.Run("matches URS flag for 5xx responses", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{Flag: errors.URS},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Upstream error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		testCases := []int{500, 502, 503, 504, 599}
		for _, code := range testCases {
			result := eo.ApplyUpstreamOverride(code, func() []byte {
				return []byte("")
			})

			require.NotNil(t, result, "status code %d", code)
			assert.Equal(t, 503, result.StatusCode)
		}
	})

	t.Run("does not match URS flag for 4xx responses", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"4xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{Flag: errors.URS},
					Response: apidef.ErrorResponse{
						Message: "Should not match",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(404, func() []byte {
			return []byte("")
		})

		assert.Nil(t, result)
	})

	t.Run("skips gateway-only flags", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{Flag: errors.AKI},
					Response: apidef.ErrorResponse{
						Message: "Should not match",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(500, func() []byte {
			return []byte("")
		})

		assert.Nil(t, result, "gateway-only flags should not match upstream responses")
	})

	t.Run("matches body field in JSON response", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.type",
						BodyValue: "timeout",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 504,
						Message:    "Timeout occurred",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(500, func() []byte {
			return []byte(`{"error": {"type": "timeout"}}`)
		})

		require.NotNil(t, result)
		assert.Equal(t, 504, result.StatusCode)
	})

	t.Run("matches message pattern", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database.*unavailable",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Database is down",
					},
				},
			},
		}

		// Compile the pattern
		for _, rules := range overrides {
			for i := range rules {
				err := rules[i].Match.Compile()
				assert.NoError(t, err)
			}
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(500, func() []byte {
			return []byte("database connection unavailable")
		})

		require.NotNil(t, result)
		assert.Equal(t, 503, result.StatusCode)
	})

	t.Run("lazy body reading - only reads when needed", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					// First rule has no body match - should not read body
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Generic error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		readBodyCalled := false
		result := eo.ApplyUpstreamOverride(500, func() []byte {
			readBodyCalled = true
			return []byte("body")
		})

		require.NotNil(t, result)
		assert.False(t, readBodyCalled, "body should not be read when rule doesn't need it")
	})

	t.Run("lazy body reading - reads when needed", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"5xx": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "TIMEOUT",
					},
					Response: apidef.ErrorResponse{
						Message: "Matched",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		readBodyCalled := false
		result := eo.ApplyUpstreamOverride(500, func() []byte {
			readBodyCalled = true
			return []byte(`{"error": {"code": "TIMEOUT"}}`)
		})

		require.NotNil(t, result)
		assert.True(t, readBodyCalled, "body should be read when rule needs body match")
	})

	t.Run("preserves original status code when override code is 0", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 0, // Don't change status code
						Message:    "Keep original code",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		result := eo.ApplyUpstreamOverride(500, func() []byte {
			return []byte("")
		})

		require.NotNil(t, result)
		assert.Equal(t, 500, result.StatusCode, "should preserve original status code")
		assert.Equal(t, 500, result.OriginalCode)
	})

	t.Run("body field matching", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"400": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "INVALID_PAYMENT",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 402,
						Message:    "Payment required",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(&APISpec{}, gw)

		// Should match
		result := eo.ApplyUpstreamOverride(400, func() []byte {
			return []byte(`{"error": {"code": "INVALID_PAYMENT"}}`)
		})
		require.NotNil(t, result)
		assert.Equal(t, 402, result.StatusCode)

		// Should not match - different code
		result = eo.ApplyUpstreamOverride(400, func() []byte {
			return []byte(`{"error": {"code": "INVALID_INPUT"}}`)
		})
		assert.Nil(t, result)

		// Should not match - field doesn't exist
		result = eo.ApplyUpstreamOverride(400, func() []byte {
			return []byte(`{"error": {}}`)
		})
		assert.Nil(t, result)
	})
}

func TestMatchesUpstreamCriteria(t *testing.T) {
	gw := createGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)

	t.Run("matches when no criteria specified", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: nil,
		}

		matches := eo.matchesUpstreamCriteria(rule, nil, 500)
		assert.True(t, matches)
	})

	t.Run("matches URS flag for 5xx", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{Flag: errors.URS},
		}

		testCases := []struct {
			code    int
			matches bool
		}{
			{500, true},
			{502, true},
			{599, true},
			{400, false},
			{404, false},
			{600, false},
		}

		for _, tc := range testCases {
			matches := eo.matchesUpstreamCriteria(rule, nil, tc.code)
			assert.Equal(t, tc.matches, matches, "status code %d", tc.code)
		}
	})

	t.Run("skips gateway-only flags", func(t *testing.T) {
		gatewayFlags := []errors.ResponseFlag{
			errors.AKI, // Auth Key Invalid
			errors.RLT, // Rate Limit
			errors.QEX, // Quota
		}

		for _, flag := range gatewayFlags {
			rule := &apidef.ErrorOverride{
				Match: &apidef.ErrorMatcher{Flag: flag},
			}

			matches := eo.matchesUpstreamCriteria(rule, nil, 500)
			assert.False(t, matches, "flag %s should not match upstream", flag)
		}
	})

	t.Run("matches body field", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				BodyField: "status",
				BodyValue: "error",
			},
		}

		body := []byte(`{"status": "error"}`)
		matches := eo.matchesUpstreamCriteria(rule, body, 500)
		assert.True(t, matches)
	})

	t.Run("does not match wrong body field key", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
		}

		body := []byte(`{"other": "value"}`)
		matches := eo.matchesUpstreamCriteria(rule, body, 500)
		assert.False(t, matches)
	})

	t.Run("does not match wrong body field value", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				BodyField: "status",
				BodyValue: "error",
			},
		}

		body := []byte(`{"status": "ok"}`)
		matches := eo.matchesUpstreamCriteria(rule, body, 500)
		assert.False(t, matches)
	})

	t.Run("matches message pattern", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "timeout",
			},
		}
		err := rule.Match.Compile()
		assert.NoError(t, err)

		body := []byte("connection timeout error")
		matches := eo.matchesUpstreamCriteria(rule, body, 500)
		assert.True(t, matches)
	})

	t.Run("returns true when no match criteria", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{},
		}

		matches := eo.matchesUpstreamCriteria(rule, nil, 500)
		assert.True(t, matches)
	})
}

func TestNeedsBodyForMatch(t *testing.T) {
	gw := createGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)

	t.Run("returns false when no match criteria", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: nil,
		}

		needs := eo.needsBodyForMatch(rule)
		assert.False(t, needs)
	})

	t.Run("returns true when body field is set", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "timeout",
			},
		}

		needs := eo.needsBodyForMatch(rule)
		assert.True(t, needs)
	})

	t.Run("returns true when message pattern is set", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				MessagePattern: "error.*timeout",
			},
		}

		needs := eo.needsBodyForMatch(rule)
		assert.True(t, needs)
	})

	t.Run("returns false when only flag is set", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Match: &apidef.ErrorMatcher{
				Flag: errors.URS,
			},
		}

		needs := eo.needsBodyForMatch(rule)
		assert.False(t, needs)
	})
}

func TestCreateOverrideResult(t *testing.T) {
	gw := createGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)

	t.Run("creates result with override code", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				StatusCode: 503,
				Message:    "Service unavailable",
				Headers:    map[string]string{"Retry-After": "60"},
			},
		}

		result := eo.createOverrideResult(rule, 500)

		assert.Equal(t, 503, result.StatusCode)
		assert.Equal(t, 500, result.OriginalCode)
		assert.Equal(t, "60", result.Headers["Retry-After"])
		assert.Equal(t, rule, result.rule)
	})

	t.Run("preserves original code when override code is 0", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				StatusCode: 0,
				Message:    "Keep original",
			},
		}

		result := eo.createOverrideResult(rule, 500)

		assert.Equal(t, 500, result.StatusCode, "should use original code")
		assert.Equal(t, 500, result.OriginalCode)
	})

	t.Run("handles nil headers", func(t *testing.T) {
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				StatusCode: 503,
				Headers:    nil,
			},
		}

		result := eo.createOverrideResult(rule, 500)

		assert.NotNil(t, result)
		assert.Nil(t, result.Headers)
	})
}
