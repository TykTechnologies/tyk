package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractMCPObjFromReq(t *testing.T) {
	t.Parallel()

	validMCPDefinition := `{
		"openapi": "3.0.3",
		"info": {
			"title": "Test MCP API",
			"version": "1.0.0"
		},
		"paths": {},
		"x-tyk-api-gateway": {
			"info": {
				"name": "test-mcp-api",
				"state": {
					"active": true
				}
			},
			"server": {
				"listenPath": {
					"value": "/test-mcp/"
				}
			},
			"upstream": {
				"url": "http://upstream.url"
			},
			"middleware": {
				"mcpTools": {
					"test-tool": {
						"allow": {
							"enabled": true
						}
					}
				}
			}
		}
	}`

	t.Run("valid MCP object extraction", func(t *testing.T) {
		t.Parallel()
		reqBody := io.NopCloser(strings.NewReader(validMCPDefinition))

		reqBodyBytes, mcpObj, err := extractMCPObjFromReq(reqBody)

		assert.NoError(t, err)
		assert.NotNil(t, mcpObj)
		assert.NotEmpty(t, reqBodyBytes)
		assert.Equal(t, "3.0.3", mcpObj.OpenAPI)
		assert.Equal(t, "Test MCP API", mcpObj.Info.Title)
	})

	t.Run("invalid JSON format", func(t *testing.T) {
		t.Parallel()
		invalidJSON := `{"openapi": "3.0.3", "info": invalid}`
		reqBody := io.NopCloser(strings.NewReader(invalidJSON))

		_, _, err := extractMCPObjFromReq(reqBody)

		assert.Error(t, err)
		assert.Equal(t, ErrRequestMalformed, err)
	})

	t.Run("array instead of object", func(t *testing.T) {
		t.Parallel()
		invalidStructure := `["array", "instead", "of", "object"]`
		reqBody := io.NopCloser(strings.NewReader(invalidStructure))

		_, _, err := extractMCPObjFromReq(reqBody)

		assert.Error(t, err)
		assert.Equal(t, ErrRequestMalformed, err)
	})

	t.Run("null body", func(t *testing.T) {
		t.Parallel()
		reqBody := io.NopCloser(strings.NewReader("null"))

		_, mcpObj, err := extractMCPObjFromReq(reqBody)

		assert.NoError(t, err)
		assert.NotNil(t, mcpObj)
	})

	t.Run("invalid OpenAPI version", func(t *testing.T) {
		t.Parallel()
		invalidVersion := `{
			"openapi": "2.0.0",
			"info": {"title": "test", "version": "1.0.0"},
			"paths": {}
		}`
		reqBody := io.NopCloser(strings.NewReader(invalidVersion))

		_, mcpObj, err := extractMCPObjFromReq(reqBody)

		assert.NoError(t, err)
		assert.NotNil(t, mcpObj)
		assert.Equal(t, "2.0.0", mcpObj.OpenAPI)
	})
}

func TestValidateMCP(t *testing.T) {
	t.Parallel()

	validMCPDefinition := `{
		"openapi": "3.0.3",
		"info": {
			"title": "Test MCP API",
			"version": "1.0.0"
		},
		"paths": {},
		"x-tyk-api-gateway": {
			"info": {
				"name": "test-mcp-api",
				"state": {
					"active": true
				}
			},
			"server": {
				"listenPath": {
					"value": "/test-mcp/"
				}
			},
			"upstream": {
				"url": "http://upstream.url"
			},
			"middleware": {
				"mcpTools": {
					"test-tool": {
						"allow": {
							"enabled": true
						}
					}
				}
			}
		}
	}`

	t.Run("valid MCP object passes validation", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("PUT request with valid MCP object", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPut, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("malformed request body", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"invalid": json}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "error")
	})

	t.Run("POST without Tyk extension returns error", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := ts.Gw.validateMCP(nextHandler)

		mcpWithoutExtension := `{
			"openapi": "3.0.3",
			"info": {"title": "Test", "version": "1.0.0"},
			"paths": {}
		}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithoutExtension))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "x-tyk-api-gateway")
	})

	t.Run("PUT without Tyk extension returns error", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := ts.Gw.validateMCP(nextHandler)

		mcpWithoutExtension := `{
			"openapi": "3.0.3",
			"info": {"title": "Test", "version": "1.0.0"},
			"paths": {}
		}`

		req := httptest.NewRequest(http.MethodPut, "/test", strings.NewReader(mcpWithoutExtension))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "x-tyk-api-gateway")
	})

	t.Run("GET request without Tyk extension passes", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		mcpWithoutExtension := `{
			"openapi": "3.0.3",
			"info": {"title": "Test", "version": "1.0.0"},
			"paths": {}
		}`

		req := httptest.NewRequest(http.MethodGet, "/test", strings.NewReader(mcpWithoutExtension))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// GET requests should pass the Tyk extension check
		assert.True(t, nextCalled, "next handler should be called for GET")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing required Tyk fields returns error", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := ts.Gw.validateMCP(nextHandler)

		invalidMCP := `{
			"openapi": "3.0.3",
			"info": {"title": "Test", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {
					"name": "test"
				}
			}
		}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(invalidMCP))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("request body is preserved for next handler", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		var capturedBody []byte
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, capturedBody, "body should be preserved")
		assert.JSONEq(t, validMCPDefinition, string(capturedBody))
	})

	t.Run("context is passed through", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		type contextKey string
		testKey := contextKey("test-key")
		testValue := "test-value"

		var capturedValue string
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(testKey); val != nil {
				capturedValue = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		ctx := context.WithValue(context.Background(), testKey, testValue)
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(validMCPDefinition))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, testValue, capturedValue, "context should be preserved")
	})

	t.Run("response headers are set correctly on error", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`invalid`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})
}

func TestValidateMCP_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty request body reader", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", &bytes.Buffer{})
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("MCP object with multiple tools", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		mcpWithMultipleTools := `{
			"openapi": "3.0.3",
			"info": {"title": "Multi-Tool MCP API", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {
					"name": "multi-tool-api",
					"state": {"active": true}
				},
				"server": {
					"listenPath": {"value": "/multi/"}
				},
				"upstream": {
					"url": "http://upstream.url"
				},
				"middleware": {
					"mcpTools": {
						"tool-one": {"allow": {"enabled": true}},
						"tool-two": {"allow": {"enabled": true}},
						"tool-three": {"allow": {"enabled": true}}
					}
				}
			}
		}`

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithMultipleTools))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DELETE request behavior", func(t *testing.T) {
		t.Parallel()

		ts := StartTest(nil)
		defer ts.Close()

		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := ts.Gw.validateMCP(nextHandler)

		mcpWithoutExtension := `{
			"openapi": "3.0.3",
			"info": {"title": "Test", "version": "1.0.0"},
			"paths": {}
		}`

		req := httptest.NewRequest(http.MethodDelete, "/test", strings.NewReader(mcpWithoutExtension))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called for DELETE")
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
