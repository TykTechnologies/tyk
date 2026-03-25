package gateway

import (
	htmltemplate "html/template"
	"net/http/httptest"
	"testing"
	texttemplate "text/template"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/errors"
)

func BenchmarkTryWriteOverride(b *testing.B) {
	b.Run("empty config - fast path", func(b *testing.B) {
		gw := &Gateway{}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: nil, // Empty - triggers fast path (map length check)
					},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			handler.tryWriteOverride(nil, req, "error message", 500)
		}
	})

	b.Run("config exists - match with direct body", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Body:       `{"error": "Service unavailable"}`,
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: overrides, // Must be set to pass fast path check
					},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			handler.tryWriteOverride(w, req, "error message", 500)
		}
	})
}

func BenchmarkApplyOverride(b *testing.B) {
	b.Run("no overrides configured", func(b *testing.B) {
		gw := &Gateway{}
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("Internal server error")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("exact code match - no additional criteria", func(b *testing.B) {
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

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("Internal server error")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("pattern match 4xx", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"4xx": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Message: "Client error",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("Not found")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 404, body)
		}
	})

	b.Run("regex pattern match", func(b *testing.B) {
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

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("database connection timeout occurred")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("regex pattern non-match", func(b *testing.B) {
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

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("network error occurred")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("JSON body field match", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"400": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "INVALID_INPUT",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 422,
						Message:    "Validation failed",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte(`{"error": {"code": "INVALID_INPUT", "message": "Field x is required"}}`)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 400, body)
		}
	})

	b.Run("multiple rules - first match", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database",
					},
					Response: apidef.ErrorResponse{
						Message: "Database error",
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "network",
					},
					Response: apidef.ErrorResponse{
						Message: "Network error",
					},
				},
				{
					Response: apidef.ErrorResponse{
						Message: "Generic error",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("database connection failed")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("large body truncation", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "error at start",
					},
					Response: apidef.ErrorResponse{
						Message: "Matched",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		largeBody := make([]byte, maxBodySizeForMatching+1000)
		copy(largeBody, []byte("error at start"))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, largeBody)
		}
	})

	b.Run("flag match - exact match", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.RLT,
					},
					Response: apidef.ErrorResponse{
						StatusCode: 429,
						Message:    "Rate limit exceeded",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 429, nil)
		}
	})

	b.Run("flag match - no classification in context", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.RLT,
					},
					Response: apidef.ErrorResponse{
						StatusCode: 429,
						Message:    "Rate limit exceeded",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		// No classification set

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 429, nil)
		}
	})

	b.Run("flag match - fallback to regex", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag:           errors.CBO,
						MessagePattern: "circuit.*breaker",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Message:    "Service unavailable",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		// Set different flag so it falls back to regex
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.UCF, "connection_failure"))
		body := []byte("circuit breaker is open")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 500, body)
		}
	})

	b.Run("multiple flag rules - first match", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.TKE,
					},
					Response: apidef.ErrorResponse{
						Message: "Token expired",
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.AMF,
					},
					Response: apidef.ErrorResponse{
						Message: "Auth field missing",
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.TKI,
					},
					Response: apidef.ErrorResponse{
						Message: "Token invalid",
					},
				},
				{
					Response: apidef.ErrorResponse{
						Message: "Unauthorized",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.TKE, "token_expired"))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 401, nil)
		}
	})

	b.Run("multiple flag rules - last match (catch-all)", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.TKE,
					},
					Response: apidef.ErrorResponse{
						Message: "Token expired",
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.AMF,
					},
					Response: apidef.ErrorResponse{
						Message: "Auth field missing",
					},
				},
				{
					Response: apidef.ErrorResponse{
						Message: "Unauthorized",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		// Set a flag that doesn't match any specific rule
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.AKI, "api_key_invalid"))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 401, nil)
		}
	})

	b.Run("flag vs regex performance comparison - flag", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						Flag: errors.RLT,
					},
					Response: apidef.ErrorResponse{
						Message: "Rate limited",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		ctx.SetErrorClassification(req, errors.NewErrorClassification(errors.RLT, "rate_limited"))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 429, nil)
		}
	})

	b.Run("flag vs regex performance comparison - regex", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"429": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "rate.*limit.*exceeded",
					},
					Response: apidef.ErrorResponse{
						Message: "Rate limited",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)
		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)
		body := []byte("Rate limit exceeded")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eo.ApplyOverride(req, 429, body)
		}
	})
}

func BenchmarkWriteOverrideResponse(b *testing.B) {
	b.Run("direct message write - JSON", func(b *testing.B) {
		gw := &Gateway{}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		result := &OverrideResult{
			StatusCode: 503,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "Service temporarily unavailable", "code": "SERVICE_DOWN"}`,
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			handler.writeOverrideResponse(w, req, result, "original error")
		}
	})

	b.Run("inline template - JSON", func(b *testing.B) {
		gw := &Gateway{}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body:    `{"error": "Error {{.StatusCode}}", "message": "{{.Message}}"}`,
				Message: "timeout",
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{
			StatusCode: 504,
			rule:       rule,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			handler.writeOverrideResponse(w, req, result, "timeout")
		}
	})

	b.Run("inline template - XML", func(b *testing.B) {
		gw := &Gateway{}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body:    `<error><code>{{.StatusCode}}</code><message>{{.Message}}</message></error>`,
				Message: "server error",
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{
			StatusCode: 500,
			rule:       rule,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationXML)
			handler.writeOverrideResponse(w, req, result, "server error")
		}
	})

	b.Run("file template - JSON", func(b *testing.B) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error_test.json").Parse(
			`{"type": "error", "status": {{.StatusCode}}, "detail": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		result := &OverrideResult{
			StatusCode: 503,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message:  "Custom error message",
					Template: "error_test",
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			handler.writeOverrideResponse(w, req, result, "original")
		}
	})

	b.Run("file template - XML", func(b *testing.B) {
		gw := &Gateway{}
		xmlTmpl := texttemplate.Must(texttemplate.New("error_test.xml").Parse(
			`<error><status>{{.StatusCode}}</status><message>{{.Message}}</message></error>`,
		))
		gw.templatesRaw = xmlTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message:  "Server error occurred",
					Template: "error_test",
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationXML)
			handler.writeOverrideResponse(w, req, result, "original")
		}
	})

	b.Run("with custom headers", func(b *testing.B) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		result := &OverrideResult{
			StatusCode: 429,
			Headers: map[string]string{
				"Retry-After":      "300",
				"X-RateLimit":      "100",
				"X-RateLimit-Used": "100",
				"X-Custom":         "value",
			},
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message: `{"error": "Too many requests"}`,
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			handler.writeOverrideResponse(w, req, result, "rate limited")
		}
	})
}

func BenchmarkWriteTemplateErrorResponse(b *testing.B) {
	b.Run("default error template - JSON", func(b *testing.B) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
		}
	})
}

func BenchmarkCompileErrorOverrides(b *testing.B) {
	b.Run("single exact code", func(b *testing.B) {
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

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			CompileErrorOverrides(overrides)
		}
	})

	b.Run("multiple exact codes", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"400": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Bad request"}},
			},
			"401": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Unauthorized"}},
			},
			"403": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Forbidden"}},
			},
			"404": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Not found"}},
			},
			"500": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Internal error"}},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			CompileErrorOverrides(overrides)
		}
	})

	b.Run("with regex patterns", func(b *testing.B) {
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
					Match: &apidef.ErrorMatcher{
						MessagePattern: "network.*error",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 502,
						Message:    "Network error",
					},
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			CompileErrorOverrides(overrides)
		}
	})

	b.Run("with inline templates", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						Body:    `{"error": "Error {{.StatusCode}}", "message": "{{.Message}}"}`,
						Message: "error message",
					},
				},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			CompileErrorOverrides(overrides)
		}
	})

	b.Run("mixed exact and patterns", func(b *testing.B) {
		overrides := apidef.ErrorOverridesMap{
			"401": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Unauthorized"}},
			},
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database",
					},
					Response: apidef.ErrorResponse{Message: "Database error"},
				},
				{Response: apidef.ErrorResponse{Message: "Generic error"}},
			},
			"4xx": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Client error"}},
			},
			"5xx": []apidef.ErrorOverride{
				{Response: apidef.ErrorResponse{Message: "Server error"}},
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			CompileErrorOverrides(overrides)
		}
	})
}

func BenchmarkErrorResponseContext(b *testing.B) {
	b.Run("detect JSON content type", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			DetectErrorResponseContext(req)
		}
	})

	b.Run("detect XML content type", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationXML)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			DetectErrorResponseContext(req)
		}
	})

	b.Run("detect JSON with charset", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, "application/json; charset=utf-8")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			DetectErrorResponseContext(req)
		}
	})
}
