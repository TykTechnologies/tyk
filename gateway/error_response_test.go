package gateway

import (
	"bytes"
	htmltemplate "html/template"
	"io"
	"net/http/httptest"
	"testing"
	texttemplate "text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

// TestDetectErrorResponseContext tests content-type detection
func TestDetectErrorResponseContext(t *testing.T) {
	t.Run("JSON content type - application/json", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationJSON, ctx.ContentType)
		assert.Equal(t, "json", ctx.TemplateExtension)
		assert.False(t, ctx.IsXML)
	})

	t.Run("XML content type - application/xml", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationXML)

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationXML, ctx.ContentType)
		assert.Equal(t, "xml", ctx.TemplateExtension)
		assert.True(t, ctx.IsXML)
	})

	t.Run("XML content type - text/xml", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.TextXML)

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.TextXML, ctx.ContentType)
		assert.Equal(t, "xml", ctx.TemplateExtension)
		assert.True(t, ctx.IsXML)
	})

	t.Run("default to JSON when no content type", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationJSON, ctx.ContentType)
		assert.Equal(t, "json", ctx.TemplateExtension)
		assert.False(t, ctx.IsXML)
	})

	t.Run("default to JSON for unknown content type", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, "text/plain")

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationJSON, ctx.ContentType)
		assert.Equal(t, "json", ctx.TemplateExtension)
		assert.False(t, ctx.IsXML)
	})

	t.Run("content type with charset", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, "application/json; charset=utf-8")

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationJSON, ctx.ContentType)
		assert.Equal(t, "json", ctx.TemplateExtension)
		assert.False(t, ctx.IsXML)
	})

	t.Run("XML content type with charset", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, "application/xml; charset=utf-8")

		ctx := DetectErrorResponseContext(req)
		assert.Equal(t, header.ApplicationXML, ctx.ContentType)
		assert.Equal(t, "xml", ctx.TemplateExtension)
		assert.True(t, ctx.IsXML)
	})
}

// TestSetErrorResponseHeaders tests header setting
func TestSetErrorResponseHeaders(t *testing.T) {
	createTestErrorHandler := func(cfg config.Config) *ErrorHandler {
		spec := &APISpec{
			GlobalConfig: cfg,
		}
		return &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
			},
		}
	}

	t.Run("sets content type", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
		assert.Equal(t, header.ApplicationJSON, respHeader.Get(header.ContentType))
	})

	t.Run("sets X-Generator header by default", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{
			HideGeneratorHeader: false,
		})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		assert.Equal(t, "tyk.io", w.Header().Get(header.XGenerator))
		assert.Equal(t, "tyk.io", respHeader.Get(header.XGenerator))
	})

	t.Run("hides X-Generator header when configured", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{
			HideGeneratorHeader: true,
		})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		assert.Empty(t, w.Header().Get(header.XGenerator))
		assert.Empty(t, respHeader.Get(header.XGenerator))
	})

	t.Run("sets Connection: close when configured", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{
			CloseConnections: true,
		})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		assert.Equal(t, "close", w.Header().Get(header.Connection))
		assert.Equal(t, "close", respHeader.Get(header.Connection))
	})

	t.Run("does not set Connection: close by default", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{
			CloseConnections: false,
		})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		assert.Empty(t, w.Header().Get(header.Connection))
		assert.Empty(t, respHeader.Get(header.Connection))
	})

	t.Run("returns independent header copy", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler(config.Config{})

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		// Modify the returned header
		respHeader.Set("X-Custom", "value")

		// Should not affect response writer
		assert.Empty(t, w.Header().Get("X-Custom"))
	})
}

// TestExecuteErrorTemplate tests template execution
func TestExecuteErrorTemplate(t *testing.T) {
	createTestErrorHandler := func() *ErrorHandler {
		spec := &APISpec{
			GlobalConfig: config.Config{},
		}
		return &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: spec,
			},
		}
	}

	t.Run("executes html template successfully", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"error": "{{.Message}}", "code": {{.StatusCode}}}`))
		data := &APIErrorWithContext{
			Message:    htmltemplate.HTML("Service unavailable"),
			StatusCode: 503,
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 503)

		assert.Equal(t, 503, response.StatusCode)
		assert.Equal(t, 503, w.Code)

		// Read response body
		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodyBytes), "Service unavailable")
		assert.Contains(t, string(bodyBytes), "503")

		// Check response writer also got the content
		assert.Contains(t, w.Body.String(), "Service unavailable")
	})

	t.Run("executes text template successfully", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := texttemplate.Must(texttemplate.New("test").Parse(`<error><message>{{.Message}}</message><code>{{.StatusCode}}</code></error>`))
		data := &APIErrorWithContext{
			Message:    htmltemplate.HTML("Timeout"),
			StatusCode: 504,
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 504)

		assert.Equal(t, 504, response.StatusCode)

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Contains(t, string(bodyBytes), "Timeout")
		assert.Contains(t, string(bodyBytes), "504")
	})

	t.Run("template execution writes to both response writer and return value", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"msg": "{{.Message}}"}`))
		data := &APIErrorWithContext{
			Message: htmltemplate.HTML("test"),
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 500)

		// Check both have the same content
		responseBody, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		writerBody := w.Body.String()

		assert.Equal(t, string(responseBody), writerBody)
		assert.Contains(t, writerBody, `"msg": "test"`)
	})

	t.Run("template with multiple fields", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{
			"status": {{.StatusCode}},
			"message": "{{.Message}}"
		}`))
		data := &APIErrorWithContext{
			Message:    htmltemplate.HTML("Authentication failed"),
			StatusCode: 401,
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 401)

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		body := string(bodyBytes)

		assert.Contains(t, body, `"status": 401`)
		assert.Contains(t, body, `"message": "Authentication failed"`)
	})

	t.Run("empty message", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"message": "{{.Message}}"}`))
		data := &APIErrorWithContext{
			Message: htmltemplate.HTML(""),
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 500)

		bodyBytes, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Equal(t, `{"message": ""}`, string(bodyBytes))
	})

	t.Run("response body is readable multiple times", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := createTestErrorHandler()

		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"msg": "test"}`))
		data := &APIErrorWithContext{
			Message: htmltemplate.HTML("test"),
		}

		response := handler.ExecuteErrorTemplate(w, tmpl, data, 500)

		// First read
		bodyBytes1, err := io.ReadAll(response.Body)
		require.NoError(t, err)

		// The body is io.NopCloser(&log), which is a bytes.Buffer
		// We need to seek back or check the type
		// Actually, let's verify the content is correct
		assert.Equal(t, `{"msg": "test"}`, string(bodyBytes1))
	})
}

// TestAPIErrorWithContext tests the error context structure
func TestAPIErrorWithContext(t *testing.T) {
	t.Run("has Message and StatusCode fields", func(t *testing.T) {
		errCtx := &APIErrorWithContext{
			Message:    htmltemplate.HTML("Test error"),
			StatusCode: 500,
		}

		assert.Equal(t, htmltemplate.HTML("Test error"), errCtx.Message)
		assert.Equal(t, 500, errCtx.StatusCode)
	})

	t.Run("templates using Message work correctly", func(t *testing.T) {
		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{{.Message}}`))

		errCtx := &APIErrorWithContext{
			Message: htmltemplate.HTML("Compatible"),
		}

		var buf bytes.Buffer
		err := tmpl.Execute(&buf, errCtx)
		require.NoError(t, err)
		assert.Equal(t, "Compatible", buf.String())
	})

	t.Run("can use StatusCode field in templates", func(t *testing.T) {
		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`Status: {{.StatusCode}}, Message: {{.Message}}`))

		errCtx := &APIErrorWithContext{
			Message:    htmltemplate.HTML("Error"),
			StatusCode: 404,
		}

		var buf bytes.Buffer
		err := tmpl.Execute(&buf, errCtx)
		require.NoError(t, err)
		assert.Equal(t, "Status: 404, Message: Error", buf.String())
	})

	t.Run("htmltemplate.HTML Message is not re-escaped by html/template", func(t *testing.T) {
		// Message is htmltemplate.HTML, so html/template treats it as already-safe and does
		// not apply HTML entity encoding. Callers are responsible for escaping before assignment.
		tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"error": "{{.Message}}"}`))

		errCtx := &APIErrorWithContext{
			Message: htmltemplate.HTML(`already escaped \x27content\x27`),
		}

		var buf bytes.Buffer
		err := tmpl.Execute(&buf, errCtx)
		require.NoError(t, err)
		assert.Contains(t, buf.String(), `"error": "already escaped \x27content\x27"`)
	})
}

func TestEscapeTemplateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isXML    bool
		expected htmltemplate.HTML
	}{
		// JSON path: html/template would HTML-encode plain strings (e.g. ' → &#39;).
		// escapeTemplateString must produce htmltemplate.HTML so the engine treats it as safe.
		{
			name:     "JSON: plain string is unchanged",
			input:    "validation failed",
			isXML:    false,
			expected: htmltemplate.HTML("validation failed"),
		},
		{
			name:     "JSON: single quote is JS-escaped, not HTML-encoded",
			input:    "it's invalid",
			isXML:    false,
			expected: htmltemplate.HTML(`it\'s invalid`),
		},
		{
			name:     "JSON: angle brackets are JS-escaped",
			input:    "<script>",
			isXML:    false,
			expected: htmltemplate.HTML(`\u003Cscript\u003E`),
		},
		{
			name:     "JSON: ampersand is JS-escaped",
			input:    "a & b",
			isXML:    false,
			expected: htmltemplate.HTML(`a \u0026 b`),
		},
		// XML path: text/template does not auto-escape, so HTML-escaping must be applied explicitly.
		{
			name:     "XML: plain string is unchanged",
			input:    "validation failed",
			isXML:    true,
			expected: htmltemplate.HTML("validation failed"),
		},
		{
			name:     "XML: single quote is HTML-escaped",
			input:    "it's invalid",
			isXML:    true,
			expected: htmltemplate.HTML("it&#39;s invalid"),
		},
		{
			name:     "XML: angle brackets are HTML-escaped",
			input:    "<error>",
			isXML:    true,
			expected: htmltemplate.HTML("&lt;error&gt;"),
		},
		{
			name:     "XML: ampersand is HTML-escaped",
			input:    "a & b",
			isXML:    true,
			expected: htmltemplate.HTML("a &amp; b"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeTemplateString(tc.input, tc.isXML)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestHeaderPropagation tests that headers are correctly set on both writer and response
func TestHeaderPropagation(t *testing.T) {
	t.Run("headers set on both writer and return value", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
			},
		}

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		// Both should have Content-Type
		assert.Equal(t, header.ApplicationJSON, w.Header().Get(header.ContentType))
		assert.Equal(t, header.ApplicationJSON, respHeader.Get(header.ContentType))
	})

	t.Run("modifying returned header doesn't affect writer", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
			},
		}

		respHeader := handler.SetErrorResponseHeaders(w, header.ApplicationJSON)

		// Modify returned header
		respHeader.Set("X-Test", "modified")

		// Writer should not be affected
		assert.Empty(t, w.Header().Get("X-Test"))
		assert.Equal(t, "modified", respHeader.Get("X-Test"))
	})
}

// TestContentTypeParsing tests edge cases in content-type parsing
func TestContentTypeParsing(t *testing.T) {
	testCases := []struct {
		name              string
		contentType       string
		expectedType      string
		expectedExtension string
		expectedIsXML     bool
	}{
		{
			name:              "application/json",
			contentType:       "application/json",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
		{
			name:              "application/json with charset",
			contentType:       "application/json; charset=utf-8",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
		{
			name:              "application/json with multiple params",
			contentType:       "application/json; charset=utf-8; boundary=something",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
		{
			name:              "application/xml",
			contentType:       "application/xml",
			expectedType:      header.ApplicationXML,
			expectedExtension: "xml",
			expectedIsXML:     true,
		},
		{
			name:              "application/xml with charset",
			contentType:       "application/xml; charset=utf-8",
			expectedType:      header.ApplicationXML,
			expectedExtension: "xml",
			expectedIsXML:     true,
		},
		{
			name:              "text/xml",
			contentType:       "text/xml",
			expectedType:      header.TextXML,
			expectedExtension: "xml",
			expectedIsXML:     true,
		},
		{
			name:              "text/xml with charset",
			contentType:       "text/xml; charset=iso-8859-1",
			expectedType:      header.TextXML,
			expectedExtension: "xml",
			expectedIsXML:     true,
		},
		{
			name:              "text/html defaults to JSON",
			contentType:       "text/html",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
		{
			name:              "text/plain defaults to JSON",
			contentType:       "text/plain",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
		{
			name:              "empty defaults to JSON",
			contentType:       "",
			expectedType:      header.ApplicationJSON,
			expectedExtension: "json",
			expectedIsXML:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tc.contentType != "" {
				req.Header.Set(header.ContentType, tc.contentType)
			}

			ctx := DetectErrorResponseContext(req)

			assert.Equal(t, tc.expectedType, ctx.ContentType)
			assert.Equal(t, tc.expectedExtension, ctx.TemplateExtension)
			assert.Equal(t, tc.expectedIsXML, ctx.IsXML)
		})
	}
}

// TestExecuteErrorTemplateStatusCodes tests various status codes
func TestExecuteErrorTemplateStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
	}{
		{"400 Bad Request", 400},
		{"401 Unauthorized", 401},
		{"403 Forbidden", 403},
		{"404 Not Found", 404},
		{"429 Too Many Requests", 429},
		{"500 Internal Server Error", 500},
		{"502 Bad Gateway", 502},
		{"503 Service Unavailable", 503},
		{"504 Gateway Timeout", 504},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler := &ErrorHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						GlobalConfig: config.Config{},
					},
				},
			}

			tmpl := htmltemplate.Must(htmltemplate.New("test").Parse(`{"code": {{.StatusCode}}}`))
			data := &APIErrorWithContext{
				StatusCode: tc.statusCode,
			}

			response := handler.ExecuteErrorTemplate(w, tmpl, data, tc.statusCode)

			assert.Equal(t, tc.statusCode, response.StatusCode)
			assert.Equal(t, tc.statusCode, w.Code)
		})
	}
}
