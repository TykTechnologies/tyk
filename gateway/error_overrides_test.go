package gateway

import (
	"html/template"
	"net/http/httptest"
	"testing"
	texttemplate "text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
)

// TestCompileErrorOverrides tests the compilation of error override rules
func TestCompileErrorOverrides(t *testing.T) {
	t.Run("nil overrides", func(t *testing.T) {
		result := CompileErrorOverrides(nil)
		assert.Nil(t, result)
	})

	t.Run("empty overrides", func(t *testing.T) {
		result := CompileErrorOverrides(config.ErrorOverridesMap{})
		assert.Nil(t, result)
	})

	t.Run("exact status code", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Code:    503,
						Message: "Service unavailable",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Contains(t, result.ByExactCode, 500)
		assert.Len(t, result.ByExactCode[500], 1)
		assert.Equal(t, 503, result.ByExactCode[500][0].Response.Code)
	})

	t.Run("pattern status code 4xx", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"4xx": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
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
		overrides := config.ErrorOverridesMap{
			"5xx": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						MessagePattern: "database.*timeout",
					},
					Response: config.ErrorResponse{
						Code:    504,
						Message: "Database timeout",
					},
				},
				{
					Response: config.ErrorResponse{
						Code:    503,
						Message: "Generic server error",
					},
				},
			},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		assert.Len(t, result.ByExactCode[500], 2)
	})

	t.Run("mixed exact and pattern codes", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"401": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Unauthorized"}},
			},
			"500": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Internal error"}},
			},
			"4xx": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Client error"}},
			},
			"5xx": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Server error"}},
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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						MessagePattern: "[invalid(regex",
					},
					Response: config.ErrorResponse{
						Message: "Should be skipped",
					},
				},
				{
					Response: config.ErrorResponse{
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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Body: "{{.InvalidSyntax",
					},
				},
				{
					Response: config.ErrorResponse{
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
		overrides := config.ErrorOverridesMap{
			"abc":  []config.ErrorOverride{{Response: config.ErrorResponse{Message: "invalid"}}},
			"50x":  []config.ErrorOverride{{Response: config.ErrorResponse{Message: "invalid pattern"}}},
			"500x": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "too long"}}},
			"500":  []config.ErrorOverride{{Response: config.ErrorResponse{Message: "valid"}}},
		}

		result := CompileErrorOverrides(overrides)
		require.NotNil(t, result)
		// Only the valid "500" rule should be compiled
		assert.Len(t, result.ByExactCode, 1)
		assert.Contains(t, result.ByExactCode, 500)
		assert.Empty(t, result.ByPrefix)
	})

	t.Run("body with template variables is compiled", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				MessagePattern: "database.*timeout",
			},
			Response: config.ErrorResponse{
				Message: "Timeout occurred",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.NotNil(t, rule.Match.CompiledPattern)
	})

	t.Run("valid rule with body template", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: "Error {{.StatusCode}}",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("invalid regex pattern", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				MessagePattern: "[invalid",
			},
		}

		err := compileSingleRule(rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid match pattern")
	})

	t.Run("invalid body template syntax", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: "{{.Invalid",
			},
		}

		err := compileSingleRule(rule)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid body template")
	})

	t.Run("no match criteria", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
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
		matcher := &config.ErrorMatcher{
			MessagePattern: "database.*error",
		}

		err := matcher.Compile()
		assert.NoError(t, err)
		assert.NotNil(t, matcher.CompiledPattern)
		assert.True(t, matcher.CompiledPattern.MatchString("database connection error"))
	})

	t.Run("invalid regex", func(t *testing.T) {
		matcher := &config.ErrorMatcher{
			MessagePattern: "[invalid(regex",
		}

		err := matcher.Compile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("empty pattern", func(t *testing.T) {
		matcher := &config.ErrorMatcher{}

		err := matcher.Compile()
		assert.NoError(t, err)
		assert.Nil(t, matcher.CompiledPattern)
	})

	t.Run("already compiled", func(t *testing.T) {
		matcher := &config.ErrorMatcher{
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
	createGateway := func(overrides config.ErrorOverridesMap) *Gateway {
		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		if compiled != nil {
			gw.SetCompiledErrorOverrides(compiled)
		}
		return gw
	}

	t.Run("no overrides configured", func(t *testing.T) {
		gw := &Gateway{}
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error message"))
		assert.Nil(t, result)
	})

	t.Run("exact status code match", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Code:    503,
						Message: "Service unavailable",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("internal error"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.Code)
		assert.Equal(t, 500, result.OriginalCode)
		assert.Equal(t, "Service unavailable", result.GetMessageForTemplate())
	})

	t.Run("pattern match 4xx", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"4xx": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Message: "Client error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 404, []byte("not found"))
		require.NotNil(t, result)
		assert.Equal(t, 404, result.Code) // No override code, keep original
		assert.Equal(t, "Client error", result.GetMessageForTemplate())
	})

	t.Run("pattern match 5xx", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"5xx": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Code:    503,
						Message: "Server error",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 502, []byte("bad gateway"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.Code)
		assert.Equal(t, "Server error", result.GetMessageForTemplate())
	})

	t.Run("exact match takes precedence over pattern", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Exact match"}},
			},
			"5xx": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Pattern match"}},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, "Exact match", result.GetMessageForTemplate())
	})

	t.Run("first matching rule wins", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						MessagePattern: "database",
					},
					Response: config.ErrorResponse{Message: "Database error"},
				},
				{
					Response: config.ErrorResponse{Message: "Generic error"},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						MessagePattern: "database.*timeout",
					},
					Response: config.ErrorResponse{
						Code:    504,
						Message: "Database timeout",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Should match
		result := eo.ApplyOverride(req, 500, []byte("database connection timeout"))
		require.NotNil(t, result)
		assert.Equal(t, 504, result.Code)

		// Should not match
		result = eo.ApplyOverride(req, 500, []byte("network error"))
		assert.Nil(t, result)
	})

	t.Run("body field matching", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"400": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "INVALID_PAYMENT",
					},
					Response: config.ErrorResponse{
						Code:    402,
						Message: "Payment required",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Should match
		body := []byte(`{"error": {"code": "INVALID_PAYMENT"}}`)
		result := eo.ApplyOverride(req, 400, body)
		require.NotNil(t, result)
		assert.Equal(t, 402, result.Code)

		// Should not match - different code
		body = []byte(`{"error": {"code": "INVALID_INPUT"}}`)
		result = eo.ApplyOverride(req, 400, body)
		assert.Nil(t, result)

		// Should not match - field doesn't exist
		body = []byte(`{"error": {}}`)
		result = eo.ApplyOverride(req, 400, body)
		assert.Nil(t, result)
	})

	t.Run("body field with nested path", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						BodyField: "metadata.error.type",
						BodyValue: "timeout",
					},
					Response: config.ErrorResponse{
						Code:    504,
						Message: "Request timeout",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"metadata": {"error": {"type": "timeout"}}}`)
		result := eo.ApplyOverride(req, 500, body)
		require.NotNil(t, result)
		assert.Equal(t, 504, result.Code)
	})

	t.Run("large body is truncated for matching", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						MessagePattern: "error at start",
					},
					Response: config.ErrorResponse{Message: "Matched"},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Create a large body (> 4KB) with pattern at start
		largeBody := make([]byte, maxBodySizeForMatching+1000)
		copy(largeBody, []byte("error at start"))

		result := eo.ApplyOverride(req, 500, largeBody)
		require.NotNil(t, result)
		assert.Equal(t, "Matched", result.GetMessageForTemplate())
	})

	t.Run("custom headers", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"429": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
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
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 429, []byte("too many requests"))
		require.NotNil(t, result)
		assert.Equal(t, "300", result.Headers["Retry-After"])
		assert.Equal(t, "100", result.Headers["X-Rate-Limit"])
		assert.Equal(t, "gateway", result.Headers["X-Error-Source"])
	})

	t.Run("no status code override preserves original", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"401": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Message: "Auth failed",
						// Code not specified
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 401, []byte("unauthorized"))
		require.NotNil(t, result)
		assert.Equal(t, 401, result.Code) // Original preserved
	})

	t.Run("non-matching status code", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{Response: config.ErrorResponse{Message: "Server error"}},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// 404 is not configured
		result := eo.ApplyOverride(req, 404, []byte("not found"))
		assert.Nil(t, result)
	})
}

// TestMatchesAdditionalCriteria tests the matching logic for different criteria
func TestMatchesAdditionalCriteria(t *testing.T) {
	eo := &ErrorOverrides{}

	t.Run("no match criteria always matches", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match:    nil,
			Response: config.ErrorResponse{Message: "test"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		matches := eo.matchesAdditionalCriteria(req, rule, []byte("any body"))
		assert.True(t, matches)
	})

	t.Run("message pattern match success", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"error": {"code": "TIMEOUT"}}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.True(t, matches)
	})

	t.Run("body field match failure - wrong value", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"error": {"code": "INVALID"}}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.False(t, matches)
	})

	t.Run("body field match failure - field not exist", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		body := []byte(`{"other": "value"}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.False(t, matches)
	})

	t.Run("body field takes priority over message pattern", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag: errors.RLT, // Rate limited
			},
			Response: config.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		// Set error classification in context
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.True(t, matches)
	})

	t.Run("flag match failure - different flag", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag: errors.RLT, // Rate limited
			},
			Response: config.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		// Set different error classification
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.QEX, "quota_exceeded"))

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.False(t, matches)
	})

	t.Run("flag match failure - no classification in context", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag: errors.RLT,
			},
			Response: config.ErrorResponse{Message: "Rate limited"},
		}
		req := httptest.NewRequest("GET", "/test", nil)
		// No error classification set

		matches := eo.matchesAdditionalCriteria(req, rule, []byte(""))
		assert.False(t, matches)
	})

	t.Run("flag takes priority over message pattern", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag:           errors.RLT,
				MessagePattern: "should not be checked",
			},
			Response: config.ErrorResponse{Message: "Rate limited"},
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
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag:           errors.RLT,
				MessagePattern: "timeout",
			},
			Response: config.ErrorResponse{Message: "Error"},
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

	t.Run("fallback to body field when flag doesn't match", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Match: &config.ErrorMatcher{
				Flag:      errors.RLT,
				BodyField: "error.code",
				BodyValue: "TIMEOUT",
			},
			Response: config.ErrorResponse{Message: "Error"},
		}
		req := httptest.NewRequest("GET", "/test", nil)

		// No classification set, body field should be checked
		body := []byte(`{"error": {"code": "TIMEOUT"}}`)
		matches := eo.matchesAdditionalCriteria(req, rule, body)
		assert.True(t, matches)
	})
}

// TestApplyOverrideWithFlag tests ApplyOverride with flag matching
func TestApplyOverrideWithFlag(t *testing.T) {
	createGateway := func(overrides config.ErrorOverridesMap) *Gateway {
		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		if compiled != nil {
			gw.SetCompiledErrorOverrides(compiled)
		}
		return gw
	}

	t.Run("flag-based override match", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"429": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						Flag: errors.RLT,
					},
					Response: config.ErrorResponse{
						Code:    429,
						Message: "Rate limit exceeded - please slow down",
						Headers: map[string]string{"Retry-After": "60"},
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		// Set rate limit classification
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		result := eo.ApplyOverride(req, 429, []byte(""))
		require.NotNil(t, result)
		assert.Equal(t, 429, result.Code)
		assert.Equal(t, "Rate limit exceeded - please slow down", result.GetMessageForTemplate())
		assert.Equal(t, "60", result.Headers["Retry-After"])
	})

	t.Run("multiple flag rules - first match wins", func(t *testing.T) {
		overrides := config.ErrorOverridesMap{
			"401": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						Flag: errors.TKE, // Token expired
					},
					Response: config.ErrorResponse{
						Message: "Token expired - please refresh",
					},
				},
				{
					Match: &config.ErrorMatcher{
						Flag: errors.AMF, // Auth field missing
					},
					Response: config.ErrorResponse{
						Message: "Authentication required",
					},
				},
				{
					// Catch-all for other 401 errors
					Response: config.ErrorResponse{
						Message: "Unauthorized",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)

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
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Match: &config.ErrorMatcher{
						Flag:           errors.CBO,         // Circuit breaker
						MessagePattern: "circuit.*breaker", // Fallback pattern
					},
					Response: config.ErrorResponse{
						Code:    503,
						Message: "Service temporarily unavailable",
					},
				},
			},
		}

		gw := createGateway(overrides)
		eo := NewErrorOverrides(nil, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		// No classification set

		// Should fall back to pattern matching
		result := eo.ApplyOverride(req, 500, []byte("circuit breaker is open"))
		require.NotNil(t, result)
		assert.Equal(t, 503, result.Code)
	})
}

// TestOverrideResult tests the OverrideResult helper methods
func TestOverrideResult(t *testing.T) {
	t.Run("ShouldWriteDirectly with plain body", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Body: `{"error": "Service unavailable"}`,
				},
			},
		}

		assert.True(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldWriteDirectly with body template variables", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: `{"error": "Code {{.StatusCode}}"}`,
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{rule: rule}
		assert.False(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldWriteDirectly with file template", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Message:  "Error message",
					Template: "error_upstream",
				},
			},
		}

		assert.False(t, result.ShouldWriteDirectly())
	})

	t.Run("ShouldUseDefaultTemplate with message only", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Message: "Custom error message",
				},
			},
		}

		assert.True(t, result.ShouldUseDefaultTemplate())
	})

	t.Run("ShouldUseDefaultTemplate false with body", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Body:    `{"error": "test"}`,
					Message: "Custom error message",
				},
			},
		}

		assert.False(t, result.ShouldUseDefaultTemplate())
	})

	t.Run("GetMessageForTemplate", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Message: "Custom error message",
				},
			},
		}

		assert.Equal(t, "Custom error message", result.GetMessageForTemplate())
	})

	t.Run("GetBody", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
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
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
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
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
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
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
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
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: `{"code": {{.StatusCode}}}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("template with only Message", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: `{"error": "{{.Message}}"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("template with both variables", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: `{"code": {{.StatusCode}}, "message": "{{.Message}}"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.True(t, rule.HasCompiledTemplate())
	})

	t.Run("body with {{ but no template vars", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: `{"json": "with {{ braces }} but not template"}`,
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.False(t, rule.HasCompiledTemplate())
	})

	t.Run("empty body", func(t *testing.T) {
		rule := &config.ErrorOverride{
			Response: config.ErrorResponse{
				Body: "",
			},
		}

		err := compileSingleRule(rule)
		assert.NoError(t, err)
		assert.False(t, rule.HasCompiledTemplate())
	})
}
