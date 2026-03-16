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

	"github.com/TykTechnologies/tyk/config"
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
						ErrorOverrides: config.ErrorOverridesMap{
							"500": []config.ErrorOverride{{}},
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
						ErrorOverrides: config.ErrorOverridesMap{
							"500": []config.ErrorOverride{{}},
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
						ErrorOverrides: config.ErrorOverridesMap{},
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
						ErrorOverrides: config.ErrorOverridesMap{
							"4xx": []config.ErrorOverride{{}},
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
}

func TestApplyOverrideToResponse(t *testing.T) {
	t.Run("updates status code", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			Code:         503,
			OriginalCode: 500,
			rule:         &config.ErrorOverride{},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		middleware.applyOverrideToResponse(res, result, req, logger)

		assert.Equal(t, 503, res.StatusCode)
	})

	t.Run("sets response headers", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		res := &http.Response{
			StatusCode: 500,
			Header:     http.Header{},
		}
		result := &OverrideResult{
			Code: 500,
			Headers: map[string]string{
				"X-Error-Code": "SERVICE_DOWN",
				"Retry-After":  "60",
			},
			rule: &config.ErrorOverride{},
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
			Code: 500,
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Body: "Custom error message",
				},
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		middleware.applyOverrideToResponse(res, result, req, logger)

		body, _ := io.ReadAll(res.Body)
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
			Code: 503,
			rule: &config.ErrorOverride{},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		logger := logrus.NewEntry(logrus.New())

		middleware.applyOverrideToResponse(res, result, req, logger)

		// Body should not be set
		assert.Nil(t, res.Body)
	})
}

func TestHasBodyConfig(t *testing.T) {
	middleware := &ResponseErrorOverrideMiddleware{}

	t.Run("returns true when body is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Body: "error message",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns true when template is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Template: "error_template",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns true when message is set", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
					Message: "Custom message",
				},
			},
		}
		assert.True(t, middleware.hasBodyConfig(result))
	})

	t.Run("returns false when no body config", func(t *testing.T) {
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{},
			},
		}
		assert.False(t, middleware.hasBodyConfig(result))
	})
}

func TestGenerateOverrideBody(t *testing.T) {
	t.Run("returns plain body when no template", func(t *testing.T) {
		middleware := &ResponseErrorOverrideMiddleware{}
		result := &OverrideResult{
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{
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
			rule: &config.ErrorOverride{
				Response: config.ErrorResponse{},
			},
		}

		errCtx := &ErrorResponseContext{}
		logger := logrus.NewEntry(logrus.New())

		body := middleware.generateOverrideBody(result, errCtx, 500, logger)
		assert.Nil(t, body)
	})
}

// Helper types for testing

type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return nil
}
