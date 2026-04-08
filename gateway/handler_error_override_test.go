package gateway

import (
	htmltemplate "html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	texttemplate "text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

func TestWriteOverrideResponse(t *testing.T) {
	createTestHandler := func() *ErrorHandler {
		gw := &Gateway{}
		spec := &APISpec{
			GlobalConfig: config.Config{},
		}
		return &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
				Gw:   gw,
			},
		}
	}

	t.Run("direct body write", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 503,
			Headers: map[string]string{
				"X-Custom": "value",
			},
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "Service unavailable"}`,
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "original error")

		assert.Equal(t, 503, w.Code)
		assert.Equal(t, 503, response.StatusCode)
		assert.Equal(t, "value", w.Header().Get("X-Custom"))
		assert.Contains(t, w.Body.String(), "Service unavailable")

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodyBytes), "Service unavailable")
	})

	t.Run("inline body template - JSON", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body:    `{"error": "Error {{.StatusCode}}", "msg": "{{.Message}}"}`,
				Message: "timeout occurred",
			},
		}
		err := compileSingleRule(rule)
		require.NoError(t, err)

		result := &OverrideResult{
			StatusCode: 504,
			rule:       rule,
		}

		response := handler.writeOverrideResponse(w, req, result, "timeout")

		assert.Equal(t, 504, w.Code)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)

		assert.Contains(t, body, `"error": "Error 504"`)
		assert.Contains(t, body, `"msg": "timeout occurred"`)
	})

	t.Run("inline body template - XML", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationXML)

		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body:    `<error><code>{{.StatusCode}}</code><msg>{{.Message}}</msg></error>`,
				Message: "server error",
			},
		}
		err := compileSingleRule(rule)
		require.NoError(t, err)

		result := &OverrideResult{
			StatusCode: 500,
			rule:       rule,
		}

		response := handler.writeOverrideResponse(w, req, result, "original error")

		assert.Equal(t, 500, w.Code)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)

		assert.Contains(t, body, "<code>500</code>")
		assert.Contains(t, body, "<msg>server error</msg>")
	})

	t.Run("file template with message", func(t *testing.T) {
		gw := &Gateway{}

		// Create test templates
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error_test.json").Parse(
			`{"type": "error", "status": {{.StatusCode}}, "detail": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		spec := &APISpec{
			GlobalConfig: config.Config{},
		}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
				Gw:   gw,
			},
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 503,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message:  "Custom error message",
					Template: "error_test",
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "original")

		assert.Equal(t, 503, w.Code)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)

		assert.Contains(t, body, `"status": 503`)
		assert.Contains(t, body, "Custom error message")
	})

	t.Run("file template XML", func(t *testing.T) {
		gw := &Gateway{}

		// Create test XML template
		xmlTmpl := texttemplate.Must(texttemplate.New("error_test.xml").Parse(
			`<error><status>{{.StatusCode}}</status><message>{{.Message}}</message></error>`,
		))
		gw.templatesRaw = xmlTmpl

		spec := &APISpec{
			GlobalConfig: config.Config{},
		}
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
				Gw:   gw,
			},
		}

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationXML)

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message:  "Server error occurred",
					Template: "error_test",
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "original")

		assert.Equal(t, 500, w.Code)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)

		assert.Contains(t, body, "<status>500</status>")
		assert.Contains(t, body, "<message>Server error occurred</message>")
	})

	t.Run("no message and no template - fallback", func(t *testing.T) {
		// Create test with default error template loaded
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

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					// No message, no template - will fallback to default
				},
			},
		}

		// Should fallback to default template with original message
		response := handler.writeOverrideResponse(w, req, result, "original error")

		assert.Equal(t, 500, response.StatusCode)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)
		assert.Contains(t, body, "original error")
	})

	t.Run("preserves original message in fallback", func(t *testing.T) {
		// Create test with default error template loaded
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

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 401,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					// Only status code override, no message
				},
			},
		}

		// The originalMsg should be used in fallback template
		response := handler.writeOverrideResponse(w, req, result, "Authentication failed")

		assert.Equal(t, 401, response.StatusCode)
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)
		assert.Contains(t, body, "Authentication failed")
	})

	t.Run("multiple custom headers", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 503,
			Headers: map[string]string{
				"Retry-After":       "600",
				"X-Error-Category":  "server",
				"X-Correlation-ID":  "abc-123",
				"X-Request-Timeout": "30s",
			},
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "Service unavailable"}`,
				},
			},
		}

		handler.writeOverrideResponse(w, req, result, "error")

		assert.Equal(t, "600", w.Header().Get("Retry-After"))
		assert.Equal(t, "server", w.Header().Get("X-Error-Category"))
		assert.Equal(t, "abc-123", w.Header().Get("X-Correlation-ID"))
		assert.Equal(t, "30s", w.Header().Get("X-Request-Timeout"))
	})
}

// TestWriteDirectOverrideResponse tests direct body writing
func TestWriteDirectOverrideResponse(t *testing.T) {
	createTestHandler := func() *ErrorHandler {
		spec := &APISpec{
			GlobalConfig: config.Config{},
		}
		return &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
			},
		}
	}

	t.Run("writes JSON body directly", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()

		respHeader := http.Header{}
		respHeader.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 503,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "Service unavailable", "code": "SERVICE_DOWN"}`,
				},
			},
		}

		response := handler.writeDirectOverrideResponse(w, result, respHeader)

		assert.Equal(t, 503, w.Code)
		assert.Equal(t, 503, response.StatusCode)
		assert.JSONEq(t, `{"error": "Service unavailable", "code": "SERVICE_DOWN"}`, w.Body.String())

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "Service unavailable", "code": "SERVICE_DOWN"}`, string(bodyBytes))
	})

	t.Run("writes XML body directly", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()

		respHeader := http.Header{}
		respHeader.Set(header.ContentType, header.ApplicationXML)

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `<error><code>500</code><message>Internal error</message></error>`,
				},
			},
		}

		response := handler.writeDirectOverrideResponse(w, result, respHeader)

		assert.Equal(t, 500, w.Code)
		assert.Contains(t, w.Body.String(), "<error>")
		assert.Contains(t, w.Body.String(), "<code>500</code>")

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodyBytes), "<message>Internal error</message>")
	})

	t.Run("writes plain text directly", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()

		respHeader := http.Header{}
		respHeader.Set(header.ContentType, "text/plain")

		result := &OverrideResult{
			StatusCode: 404,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: "Not found",
				},
			},
		}

		response := handler.writeDirectOverrideResponse(w, result, respHeader)

		assert.Equal(t, 404, w.Code)
		assert.Equal(t, "Not found", w.Body.String())

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Equal(t, "Not found", string(bodyBytes))
	})

	t.Run("empty body", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()

		respHeader := http.Header{}
		respHeader.Set(header.ContentType, header.ApplicationJSON)

		result := &OverrideResult{
			StatusCode: 204,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: "",
				},
			},
		}

		response := handler.writeDirectOverrideResponse(w, result, respHeader)

		assert.Equal(t, 204, w.Code)
		assert.Empty(t, w.Body.String())

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Empty(t, string(bodyBytes))
	})

	t.Run("preserves headers", func(t *testing.T) {
		handler := createTestHandler()
		w := httptest.NewRecorder()

		respHeader := http.Header{}
		respHeader.Set(header.ContentType, header.ApplicationJSON)
		respHeader.Set("X-Custom", "preserved")

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "test"}`,
				},
			},
		}

		response := handler.writeDirectOverrideResponse(w, result, respHeader)

		// Response should have the headers
		assert.Equal(t, header.ApplicationJSON, response.Header.Get(header.ContentType))
		assert.Equal(t, "preserved", response.Header.Get("X-Custom"))
	})
}

// TestOverrideResultBehavior tests the behavior determination of OverrideResult
func TestOverrideResultBehavior(t *testing.T) {
	t.Run("GetTemplateExecutor priority - body wins over template", func(t *testing.T) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error_file.json").Parse(`{"file": true}`))
		gw.templates = jsonTmpl

		// Rule has both inline body template AND file template - body should win
		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body:     `{"inline": "{{.StatusCode}}"}`,
				Template: "error_file",
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{rule: rule}
		ctx := &ErrorResponseContext{
			IsXML:             false,
			TemplateExtension: "json",
		}

		tmpl := result.GetTemplateExecutor(gw, ctx)
		require.NotNil(t, tmpl)

		// Should use inline body template, not file template
		htmlTmpl, ok := tmpl.(*htmltemplate.Template)
		require.True(t, ok)
		assert.Equal(t, "body", htmlTmpl.Name())
	})

	t.Run("GetTemplateExecutor - inline body template", func(t *testing.T) {
		gw := &Gateway{}

		rule := &apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				Body: `{"status": {{.StatusCode}}}`,
			},
		}
		_ = compileSingleRule(rule)

		result := &OverrideResult{rule: rule}
		ctx := &ErrorResponseContext{
			IsXML:             false,
			TemplateExtension: "json",
		}

		tmpl := result.GetTemplateExecutor(gw, ctx)
		require.NotNil(t, tmpl)

		// Should be inline compiled template
		_, ok := tmpl.(*htmltemplate.Template)
		assert.True(t, ok)
	})

	t.Run("GetTemplateExecutor - nil for plain body", func(t *testing.T) {
		gw := &Gateway{}

		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"plain": "body"}`,
				},
			},
		}
		ctx := &ErrorResponseContext{IsXML: false}

		tmpl := result.GetTemplateExecutor(gw, ctx)
		assert.Nil(t, tmpl)
	})

	t.Run("GetTemplateExecutor - nil when no message and no template", func(t *testing.T) {
		gw := &Gateway{}

		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{},
			},
		}
		ctx := &ErrorResponseContext{IsXML: false}

		tmpl := result.GetTemplateExecutor(gw, ctx)
		assert.Nil(t, tmpl)
	})
}

// TestErrorOverrideEdgeCases tests edge cases and error conditions
func TestErrorOverrideEdgeCases(t *testing.T) {
	t.Run("override with zero status code preserves original", func(t *testing.T) {
		overrides := apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Response: apidef.ErrorResponse{
						StatusCode: 0, // Not set
						Message:    "Error occurred",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)

		eo := NewErrorOverrides(&APISpec{}, gw)
		req := httptest.NewRequest("GET", "/test", nil)

		result := eo.ApplyOverride(req, 500, []byte("error"))
		require.NotNil(t, result)
		assert.Equal(t, 500, result.StatusCode) // Original preserved
		assert.Equal(t, 500, result.OriginalCode)
	})

	t.Run("empty headers map", func(t *testing.T) {
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
			},
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)

		result := &OverrideResult{
			StatusCode: 500,
			Headers:    map[string]string{},
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "test"}`,
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "error")
		assert.Equal(t, 500, response.StatusCode)
	})

	t.Run("nil headers map", func(t *testing.T) {
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
			},
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)

		result := &OverrideResult{
			StatusCode: 500,
			Headers:    nil,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: `{"error": "test"}`,
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "error")
		assert.Equal(t, 500, response.StatusCode)
	})

	t.Run("very long body", func(t *testing.T) {
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
			},
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		// Create a very long body
		longBody := `{"error": "` + string(make([]byte, 10000)) + `"}`

		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: longBody,
				},
			},
		}

		response := handler.writeOverrideResponse(w, req, result, "error")
		assert.Equal(t, 500, response.StatusCode)
		assert.Equal(t, len(longBody), w.Body.Len())
	})
}
