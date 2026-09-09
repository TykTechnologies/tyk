package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestLazyBodyReader(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	t.Run("reads body lazily", func(t *testing.T) {
		bodyContent := []byte("test body content")
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)

		// Body should not be read yet
		assert.False(t, reader.read)

		// First read
		result := reader.Read()
		assert.Equal(t, bodyContent, result)
		assert.True(t, reader.read)

		// Second read should return cached data
		result2 := reader.Read()
		assert.Equal(t, bodyContent, result2)
	})

	t.Run("reads body only once", func(t *testing.T) {
		bodyContent := []byte("test content")
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)

		// Call Read multiple times
		result1 := reader.Read()
		result2 := reader.Read()
		result3 := reader.Read()

		// All calls should return the same cached data
		assert.Equal(t, bodyContent, result1)
		assert.Equal(t, bodyContent, result2)
		assert.Equal(t, bodyContent, result3)
		assert.Equal(t, result1, result2)
		assert.Equal(t, result2, result3)
	})

	t.Run("respects maxBodySizeForMatching limit", func(t *testing.T) {
		largeBody := make([]byte, maxBodySizeForMatching+1000)
		for i := range largeBody {
			largeBody[i] = 'x'
		}

		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(largeBody)), logger)
		result := reader.Read()

		// Should be truncated to maxBodySizeForMatching
		assert.Len(t, result, maxBodySizeForMatching)
	})

	t.Run("handles read error gracefully", func(t *testing.T) {
		errorReader := &errorReadCloser{err: io.ErrUnexpectedEOF}
		reader := newLazyBodyReader(errorReader, logger)

		result := reader.Read()
		assert.Nil(t, result)
	})

	t.Run("RestoreIfRead restores body when read", func(t *testing.T) {
		bodyContent := []byte("test body")
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)

		// Read the body
		reader.Read()

		// Restore to response
		res := &http.Response{}
		reader.RestoreIfRead(res)

		// Should be able to read from restored body
		restored, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Equal(t, bodyContent, restored)
	})

	t.Run("RestoreIfRead preserves full body for large responses", func(t *testing.T) {
		// Create body larger than maxBodySizeForMatching
		largeBody := make([]byte, maxBodySizeForMatching+5000)
		for i := range largeBody {
			largeBody[i] = byte('a' + (i % 26))
		}

		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(largeBody)), logger)

		// Read (will only read first maxBodySizeForMatching bytes)
		truncated := reader.Read()
		assert.Len(t, truncated, maxBodySizeForMatching)

		// Restore to response
		res := &http.Response{}
		reader.RestoreIfRead(res)

		// Should be able to read FULL body (not just truncated part)
		restored, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Equal(t, largeBody, restored, "Full body should be restored, not truncated")
	})

	t.Run("CloseOriginal closes the underlying body", func(t *testing.T) {
		closeCalled := false
		mockCloser := &mockReadCloser{
			reader: bytes.NewReader([]byte("test")),
			onClose: func() error {
				closeCalled = true
				return nil
			},
		}

		reader := newLazyBodyReader(mockCloser, logger)
		reader.CloseOriginal()

		assert.True(t, closeCalled, "Close should be called on original body")
	})

	t.Run("RestoreIfRead does nothing when not read", func(t *testing.T) {
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader([]byte("test"))), logger)

		// Don't read the body
		res := &http.Response{}
		reader.RestoreIfRead(res)

		// Body should not be set
		assert.Nil(t, res.Body)
	})
}

func TestShouldProcessResponse(t *testing.T) {
	t.Run("processes error responses with overrides configured", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"500": []apidef.ErrorOverride{{}},
						},
					},
				},
			},
		}

		res := &http.Response{StatusCode: 500}
		assert.True(t, middleware.shouldProcessResponse(res))
	})

	t.Run("skips successful responses", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"500": []apidef.ErrorOverride{{}},
						},
					},
				},
			},
		}

		testCases := []int{200, 201, 204, 301, 302, 304, 399}
		for _, code := range testCases {
			res := &http.Response{StatusCode: code}
			assert.False(t, middleware.shouldProcessResponse(res), "status code %d", code)
		}
	})

	t.Run("skips when no overrides configured", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{},
					},
					APIDefinition: &apidef.APIDefinition{},
				},
			},
		}

		res := &http.Response{StatusCode: 500}
		assert.False(t, middleware.shouldProcessResponse(res))
	})

	t.Run("skips when API-level override is disabled", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"500": []apidef.ErrorOverride{{}},
						},
						ErrorOverridesDisabled: true,
					},
				},
			},
		}

		res := &http.Response{StatusCode: 500}
		assert.False(t, middleware.shouldProcessResponse(res))
	})

	t.Run("processes all error status codes", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"4xx": []apidef.ErrorOverride{{}},
						},
					},
				},
			},
		}

		testCases := []int{400, 401, 403, 404, 429, 499, 500, 502, 503, 504, 599}
		for _, code := range testCases {
			res := &http.Response{StatusCode: code}
			assert.True(t, middleware.shouldProcessResponse(res), "status code %d", code)
		}
	})

	t.Run("processes error responses with API-level overrides configured", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"500": []apidef.ErrorOverride{{}},
						},
					},
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{},
					},
				},
			},
		}

		res := &http.Response{StatusCode: 500}
		assert.True(t, middleware.shouldProcessResponse(res))
	})

	t.Run("processes error responses with both global and API-level overrides", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{
			BaseTykResponseHandler: BaseTykResponseHandler{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"404": []apidef.ErrorOverride{{}},
						},
					},
					GlobalConfig: config.Config{
						ErrorOverrides: apidef.ErrorOverridesMap{
							"500": []apidef.ErrorOverride{{}},
						},
					},
				},
			},
		}

		res404 := &http.Response{StatusCode: 404}
		assert.True(t, middleware.shouldProcessResponse(res404))

		res500 := &http.Response{StatusCode: 500}
		assert.True(t, middleware.shouldProcessResponse(res500))
	})
}

func TestApplyOverrideToResponse(t *testing.T) {
	t.Run("updates status code", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			StatusCode:   503,
			OriginalCode: 500,
			rule:         &apidef.ErrorOverride{},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		bodyReplaced := middleware.applyOverrideToResponse(res, result, req, logger)

		assert.Equal(t, 503, res.StatusCode)
		assert.False(t, bodyReplaced, "Should return false when no body config")
	})

	t.Run("sets response headers", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			StatusCode: 500,
			Headers: map[string]string{
				"X-Error-Code": "SERVICE_DOWN",
				"Retry-After":  "60",
			},
			rule: &apidef.ErrorOverride{},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		middleware.applyOverrideToResponse(res, result, req, logger)

		assert.Equal(t, "SERVICE_DOWN", res.Header.Get("X-Error-Code"))
		assert.Equal(t, "60", res.Header.Get("Retry-After"))
	})

	t.Run("replaces response body with plain text", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			StatusCode: 500,
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: "Custom error message",
				},
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		bodyReplaced := middleware.applyOverrideToResponse(res, result, req, logger)

		assert.True(t, bodyReplaced, "Should return true when body is replaced")
		body, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Custom error message", string(body))
		assert.Equal(t, int64(len("Custom error message")), res.ContentLength)
	})

	t.Run("skips body replacement when no body config", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			StatusCode: 503,
			rule:       &apidef.ErrorOverride{},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		bodyReplaced := middleware.applyOverrideToResponse(res, result, req, logger)

		assert.False(t, bodyReplaced, "Should return false when no body config")
		// Body should not be set
		assert.Nil(t, res.Body)
	})
}

func TestHasBodyConfig(t *testing.T) {
	middleware := &ResponseErrorOverrideMiddleware{}

	t.Run("returns true when body is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: "error message",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns true when template is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Template: "error_template",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns true when message is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Message: "Custom message",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns false when no body config", func(t *testing.T) {
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{},
			},
		}
		assert.False(t, middleware.hasBodyConfig(result))
	})
}

func TestGenerateOverrideBody(t *testing.T) {
	t.Run("returns plain body when no template", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{
					Body: "Plain error text",
				},
			},
		}

		errCtx := &ErrorResponseContext{ContentType: "text/plain"}
		logger := logrus.NewEntry(logrus.New())

		body := middleware.generateOverrideBody(result, errCtx, 500, logger)
		assert.Equal(t, []byte("Plain error text"), body)
	})

	t.Run("returns nil when no body and no template", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		result := &OverrideResult{
			rule: &apidef.ErrorOverride{
				Response: apidef.ErrorResponse{},
			},
		}

		errCtx := &ErrorResponseContext{}
		logger := logrus.NewEntry(logrus.New())

		body := middleware.generateOverrideBody(result, errCtx, 500, logger)
		assert.Nil(t, body)
	})
}

func TestUpstreamErrorOverride_APILevel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_, err := w.Write([]byte(`{"upstream":"error"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"503": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{
					StatusCode: 503,
					Body:       `{"error":"api-override"}`,
				},
			}},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{{
		Path:      "/",
		Code:      503,
		BodyMatch: `"api-override"`,
	}}...)
}

func TestUpstreamErrorOverride_DisableReturnsUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_, err := w.Write([]byte(`{"upstream":"error"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"503": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{
					StatusCode: 503,
					Body:       `{"error":"api-override"}`,
				},
			}},
		}
		spec.ErrorOverridesDisabled = true
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{{
		Path:      "/",
		Code:      503,
		BodyMatch: `{"upstream":"error"}`,
	}}...)
}

func TestUpstreamErrorOverride_APIPrecedenceOverGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_, err := w.Write([]byte(`{"upstream":"error"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
		"503": []apidef.ErrorOverride{{
			Response: apidef.ErrorResponse{
				StatusCode: 503,
				Body:       `{"source":"gateway"}`,
			},
		}},
	}
	ts.Gw.SetConfig(globalConf)
	ts.Gw.SetCompiledErrorOverrides(CompileErrorOverrides(globalConf.ErrorOverrides))

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"503": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{
					StatusCode: 503,
					Body:       `{"source":"api"}`,
				},
			}},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{{
		Path:      "/",
		Code:      503,
		BodyMatch: `"api"`,
	}}...)
}

func TestUpstreamErrorOverride_GatewayFallback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(502)
		_, err := w.Write([]byte(`{"upstream":"bad gateway"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
		"502": []apidef.ErrorOverride{{
			Response: apidef.ErrorResponse{
				StatusCode: 502,
				Body:       `{"source":"gateway-fallback"}`,
			},
		}},
	}
	ts.Gw.SetConfig(globalConf)
	ts.Gw.SetCompiledErrorOverrides(CompileErrorOverrides(globalConf.ErrorOverrides))

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"404": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{Body: `{"error":"not found"}`},
			}},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{{
		Path:      "/",
		Code:      502,
		BodyMatch: `"gateway-fallback"`,
	}}...)
}

func TestUpstreamErrorOverride_APILevelPatternMatching(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/401":
			w.WriteHeader(401)
		case "/403":
			w.WriteHeader(403)
		case "/500":
			w.WriteHeader(500)
		case "/503":
			w.WriteHeader(503)
		}
		_, err := w.Write([]byte(`{"upstream":"error"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"4xx": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{Body: `{"error":"client-error"}`},
			}},
			"5xx": []apidef.ErrorOverride{{
				Response: apidef.ErrorResponse{Body: `{"error":"server-error"}`},
			}},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{
		{Path: "/401", Code: 401, BodyMatch: `"client-error"`},
		{Path: "/403", Code: 403, BodyMatch: `"client-error"`},
		{Path: "/500", Code: 500, BodyMatch: `"server-error"`},
		{Path: "/503", Code: 503, BodyMatch: `"server-error"`},
	}...)
}

func TestUpstreamErrorOverride_APILevelBodyFieldMatching(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)

		var err error
		switch r.URL.Path {
		case "/db-error":
			_, err = w.Write([]byte(`{"error":{"code":"DB_CONN_FAILED","message":"Database unavailable"}}`))
		case "/cache-error":
			_, err = w.Write([]byte(`{"error":{"code":"CACHE_MISS","message":"Cache unavailable"}}`))
		default:
			_, err = w.Write([]byte(`{"error":{"code":"UNKNOWN"}}`))
		}

		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "DB_CONN_FAILED",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Body:       `{"error":"database-override"}`,
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						BodyField: "error.code",
						BodyValue: "CACHE_MISS",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 500,
						Body:       `{"error":"cache-override"}`,
					},
				},
			},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{
		{Path: "/db-error", Code: 503, BodyMatch: `"database-override"`},
		{Path: "/cache-error", Code: 500, BodyMatch: `"cache-override"`},
		{Path: "/other", Code: 500, BodyNotMatch: `"override"`}, // No match = original body
	}...)
}

func TestUpstreamErrorOverride_APILevelMessagePattern(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)

		var err error

		switch r.URL.Path {
		case "/timeout":
			_, err = w.Write([]byte(`Connection timeout after 30s`))
		case "/oom":
			_, err = w.Write([]byte(`OutOfMemoryError: Java heap space`))
		default:
			_, err = w.Write([]byte(`Generic error`))
		}

		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "(?i)timeout",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 504,
						Body:       `{"error":"gateway-timeout"}`,
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "(?i)OutOfMemory",
					},
					Response: apidef.ErrorResponse{
						StatusCode: 503,
						Body:       `{"error":"service-overloaded"}`,
					},
				},
			},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{
		{Path: "/timeout", Code: 504, BodyMatch: `"gateway-timeout"`},
		{Path: "/oom", Code: 503, BodyMatch: `"service-overloaded"`},
		{Path: "/other", Code: 500, BodyMatch: `Generic error`}, // No match = original
	}...)
}

func TestUpstreamErrorOverride_APILevelFirstMatchWins(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, err := w.Write([]byte(`{"error":"database connection failed"}`))
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
		spec.ErrorOverrides = apidef.ErrorOverridesMap{
			"500": []apidef.ErrorOverride{
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "database",
					},
					Response: apidef.ErrorResponse{
						Body: `{"error":"first-rule"}`,
					},
				},
				{
					Match: &apidef.ErrorMatcher{
						MessagePattern: "connection",
					},
					Response: apidef.ErrorResponse{
						Body: `{"error":"second-rule"}`,
					},
				},
				{
					Response: apidef.ErrorResponse{
						Body: `{"error":"catch-all"}`,
					},
				},
			},
		}
		spec.SetCompiledErrorOverrides(CompileErrorOverrides(spec.ErrorOverrides))
	})

	ts.Run(t, []test.TestCase{{
		Path:      "/",
		Code:      500,
		BodyMatch: `"first-rule"`,
	}}...)
}

// Helper types for testing

type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read(_ []byte) (n int, err error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return nil
}

type mockReadCloser struct {
	reader  io.Reader
	onClose func() error
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockReadCloser) Close() error {
	if m.onClose != nil {
		return m.onClose()
	}
	return nil
}
