package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
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

func TestHandleGetMCPListOAS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create multiple MCP APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "mcp-1"
			spec.Name = "MCP API 1"
			spec.MarkAsMCP()
		},
		func(spec *APISpec) {
			spec.APIID = "mcp-2"
			spec.Name = "MCP API 2"
			spec.MarkAsMCP()
		},
		func(spec *APISpec) {
			spec.APIID = "regular-oas"
			spec.Name = "Regular OAS API"
			spec.IsOAS = true
		},
	)

	t.Run("returns only MCP APIs", func(t *testing.T) {
		obj, code := ts.Gw.handleGetMCPListOAS()

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		assert.Len(t, apisList, 2, "Should return exactly 2 MCP APIs")
	})

	t.Run("returns empty list when no MCP APIs exist", func(t *testing.T) {
		// Create a new gateway with no MCP APIs
		ts2 := StartTest(nil)
		defer ts2.Close()

		ts2.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.APIID = "regular-only"
				spec.Name = "Regular API"
				spec.IsOAS = true
			},
		)

		obj, code := ts2.Gw.handleGetMCPListOAS()

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok)
		assert.Len(t, apisList, 0, "Should return empty list")
	})
}

func TestMCPListHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create test MCP APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "mcp-test-1"
			spec.Name = "MCP Test 1"
			spec.MarkAsMCP()
		},
	)

	t.Run("returns MCP list successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tyk/mcps", nil)
		w := httptest.NewRecorder()

		ts.Gw.mcpListHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
		assert.NotEmpty(t, w.Body.String())
	})
}

func TestMCPUpdateHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test MCP API
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "mcp-update-test"
			spec.Name = "MCP Update Test"
			spec.MarkAsMCP()
		},
	)

	validMCPUpdate := `{
		"openapi": "3.0.3",
		"info": {
			"title": "Updated MCP",
			"version": "1.0.0"
		},
		"paths": {},
		"x-tyk-api-gateway": {
			"info": {
				"id": "mcp-update-test",
				"name": "updated-name",
				"state": {
					"active": true
				}
			},
			"server": {
				"listenPath": {
					"value": "/updated/"
				}
			},
			"upstream": {
				"url": "http://updated.url"
			},
			"middleware": {
				"mcpTools": {
					"tool": {
						"allow": {
							"enabled": true
						}
					}
				}
			}
		}
	}`

	t.Run("updates MCP API successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/mcps/mcp-update-test", strings.NewReader(validMCPUpdate))
		w := httptest.NewRecorder()

		// Mock mux.Vars
		req = mux.SetURLVars(req, map[string]string{"apiID": "mcp-update-test"})

		ts.Gw.mcpUpdateHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "modified")
	})

	t.Run("returns 400 for invalid API ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/mcps/../../../etc/passwd", strings.NewReader(validMCPUpdate))
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "../../../etc/passwd"})

		ts.Gw.mcpUpdateHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid API ID")
	})
}

func TestMCPDeleteHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("deletes MCP API successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/tyk/mcps/test-api", nil)
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "test-api"})

		ts.Gw.mcpDeleteHandler(w, req)

		assert.NotEqual(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("rejects invalid API ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/tyk/mcps/../../etc/passwd", nil)
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "../../etc/passwd"})

		ts.Gw.mcpDeleteHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid API ID")
	})
}
