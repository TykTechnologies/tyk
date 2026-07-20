package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func newMCPTestGateway(t *testing.T, appPath ...string) *Gateway {
	t.Helper()

	var path string
	if len(appPath) > 0 {
		path = appPath[0]
	} else {
		path = t.TempDir()
	}

	gw := &Gateway{apisByID: map[string]*APISpec{}}
	gw.SetConfig(config.Config{
		AppPath:    path,
		HostName:   "localhost",
		ListenPort: 8080,
	})
	return gw
}

func newValidateMCPHandler(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	t.Helper()

	return newMCPTestGateway(t).validateMCP(next)
}

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
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("PUT request with valid MCP object", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPut, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("malformed request body", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"invalid": json}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "error")
	})

	t.Run("POST without Tyk extension returns error", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

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
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

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
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

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
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

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
		var capturedBody []byte
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			capturedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(validMCPDefinition))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, capturedBody, "body should be preserved")
		assert.JSONEq(t, validMCPDefinition, string(capturedBody))
	})

	t.Run("context is passed through", func(t *testing.T) {
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

		handler := newValidateMCPHandler(t, nextHandler)

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
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`invalid`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})
}

func TestValidateMCP_EdgeCases(t *testing.T) {
	t.Run("empty request body reader", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", &bytes.Buffer{})
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("MCP object with multiple tools", func(t *testing.T) {
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

		handler := newValidateMCPHandler(t, nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithMultipleTools))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DELETE request behavior", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

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

func pairedMCPProxyOAS(proxyID, orgID, restID string) *oas.OAS {
	doc := &oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: proxyID, Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    proxyID,
			OrgID: orgID,
			Name:  proxyID,
			State: oas.State{Active: true},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/" + proxyID + "/"},
		},
		Upstream: oas.Upstream{URL: oas.AdapterLoopURL(restID)},
	})
	return doc
}

func restSourceSpec(apiID, orgID string, isOAS bool) *APISpec {
	doc := oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
		Paths: openapi3.NewPaths(
			openapi3.WithPath("/orders", &openapi3.PathItem{
				Get:  &openapi3.Operation{OperationID: "list_orders", Summary: "list orders"},
				Post: &openapi3.Operation{OperationID: "create_order", Summary: "create order"},
			}),
		),
	}}
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: apiID,
			OrgID: orgID,
			IsOAS: isOAS,
		},
		OAS: doc,
	}
}

func mcpPrimitiveNames(primitives []oas.TykMCPServerPrimitive) []string {
	names := make([]string, 0, len(primitives))
	for _, primitive := range primitives {
		names = append(names, primitive.Name)
	}
	return names
}

func mcpPrimitiveByName(primitives []oas.TykMCPServerPrimitive, name string) *oas.TykMCPServerPrimitive {
	for i := range primitives {
		if primitives[i].Name == name {
			return &primitives[i]
		}
	}
	return nil
}

func mcpManagedTestSpec(apiID string) *APISpec {
	apiDef := &apidef.APIDefinition{
		APIID: apiID,
		Name:  apiID,
		IsOAS: true,
		Proxy: apidef.ProxyConfig{
			ListenPath: "/" + apiID + "/",
			TargetURL:  "http://upstream.url",
		},
	}
	apiDef.MarkAsMCP()

	return &APISpec{
		APIDefinition: apiDef,
		OAS: oas.OAS{T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
			Paths:   openapi3.NewPaths(),
		}},
	}
}

func TestPairedMCPAdapterTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		target        string
		wantAdapterID string
		wantRestAPIID string
		wantOK        bool
	}{
		{
			name:          "accepts canonical mcp path",
			target:        "tyk://rest-1/mcp",
			wantAdapterID: "rest-1",
			wantRestAPIID: "rest-1",
			wantOK:        true,
		},
		{
			name:          "accepts id-prefixed host",
			target:        "tyk://id:rest-1/mcp/",
			wantAdapterID: "rest-1",
			wantRestAPIID: "rest-1",
			wantOK:        true,
		},
		{
			name:          "accepts fallback suffix target",
			target:        "tyk://rest-1__mcp-server",
			wantAdapterID: "rest-1__mcp-server",
			wantRestAPIID: "rest-1",
			wantOK:        true,
		},
		{
			name:   "rejects non mcp path",
			target: "tyk://rest-1/not-mcp",
		},
		{
			name:   "rejects non tyk scheme",
			target: "https://rest-1/mcp",
		},
		{
			name:   "rejects empty source api id",
			target: "tyk:///mcp",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adapterID, restAPIID, ok := pairedMCPAdapterTarget(tt.target)

			assert.Equal(t, tt.wantAdapterID, adapterID)
			assert.Equal(t, tt.wantRestAPIID, restAPIID)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestValidatePairedMCPAdapterUpstream(t *testing.T) {
	t.Parallel()

	t.Run("allows OAS source in same org", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1": restSourceSpec("rest-1", "org-1", true),
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))

		assert.Empty(t, msg)
		assert.Zero(t, code)
	})

	t.Run("rejects missing source", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{apisByID: map[string]*APISpec{}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-1", "org-1", "missing-rest"))

		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, msg, "missing-rest")
	})

	t.Run("rejects Classic source", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1": restSourceSpec("rest-1", "org-1", false),
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))

		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, msg, "Classic")
	})

	t.Run("rejects cross org source", func(t *testing.T) {
		t.Parallel()

		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1": restSourceSpec("rest-1", "org-1", true),
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-1", "org-2", "rest-1"))

		assert.Equal(t, http.StatusForbidden, code)
		assert.Contains(t, msg, "different OrgID")
	})

	t.Run("allows multiple same org proxies for same source", func(t *testing.T) {
		t.Parallel()

		existingProxy := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID: "proxy-1",
				OrgID: "org-1",
				IsOAS: true,
				Proxy: apidef.ProxyConfig{TargetURL: oas.AdapterLoopURL("rest-1")},
			},
			OAS: *pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"),
		}
		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1":  restSourceSpec("rest-1", "org-1", true),
			"proxy-1": existingProxy,
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-2", "org-1", "rest-1"))

		assert.Empty(t, msg)
		assert.Zero(t, code)
	})

	t.Run("rejects invalid catalogue config", func(t *testing.T) {
		t.Parallel()

		proxy := pairedMCPProxyOAS("proxy-1", "org-1", "rest-1")
		proxy.SetTykMCPServerExtension(&oas.TykMCPServer{
			Primitives: []oas.TykMCPServerPrimitive{
				{
					Source:     oas.TykMCPServerSource{OperationID: "list_orders"},
					Parameters: []oas.TykMCPServerParameter{{Param: "missing_param", Name: "missing"}},
				},
			},
		})
		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1": restSourceSpec("rest-1", "org-1", true),
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), proxy)

		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, msg, "missing_param")
	})

	t.Run("rejects alias conflicts across same org proxies", func(t *testing.T) {
		t.Parallel()

		existingOAS := pairedMCPProxyOAS("proxy-1", "org-1", "rest-1")
		existingOAS.SetTykMCPServerExtension(&oas.TykMCPServer{
			Primitives: []oas.TykMCPServerPrimitive{
				{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Allow: boolPtr(true)},
			},
		})
		incomingOAS := pairedMCPProxyOAS("proxy-2", "org-1", "rest-1")
		incomingOAS.SetTykMCPServerExtension(&oas.TykMCPServer{
			Primitives: []oas.TykMCPServerPrimitive{
				{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Name: "orders", Allow: boolPtr(true)},
			},
		})

		gw := &Gateway{apisByID: map[string]*APISpec{
			"rest-1": restSourceSpec("rest-1", "org-1", true),
			"proxy-1": {
				APIDefinition: &apidef.APIDefinition{
					APIID: "proxy-1",
					OrgID: "org-1",
					IsOAS: true,
					Proxy: apidef.ProxyConfig{TargetURL: oas.AdapterLoopURL("rest-1")},
				},
				OAS: *existingOAS,
			},
		}}

		msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), incomingOAS)

		assert.Equal(t, http.StatusBadRequest, code)
		assert.Contains(t, msg, "alias conflict")
	})
}

func TestValidatePairedMCPAdapterUpstream_LogsDeriveWarnings(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)
	originalLog := log
	log = logger
	t.Cleanup(func() {
		log = originalLog
	})

	rest := restSourceSpec("rest-1", "org-1", true)
	rest.OAS.Paths = openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: "list_orders", Summary: "list orders"},
		}),
		openapi3.WithPath("/skipped", &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: "blocked_orders", Summary: "blocked orders"},
		}),
	)
	rest.OAS.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"blocked_orders": {Block: &oas.Allowance{Enabled: true}},
			},
		},
	})
	gw := &Gateway{apisByID: map[string]*APISpec{
		"rest-1": rest,
	}}

	msg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))

	require.Empty(t, msg)
	require.Zero(t, code)

	var warningEntry *logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == "REST-as-MCP derivation warning" {
			warningEntry = entry
			break
		}
	}
	require.NotNil(t, warningEntry)
	assert.Equal(t, "proxy-1", warningEntry.Data["api_id"])
	assert.Equal(t, "rest-1", warningEntry.Data["rest_api_id"])
	assert.Equal(t, "blocked_orders", warningEntry.Data["operation"])
	assert.Equal(t, "GET", warningEntry.Data["method"])
	assert.Equal(t, "/skipped", warningEntry.Data["path"])
	assert.Equal(t, "operation marked blocked - skipped", warningEntry.Data["reason"])
}

func TestHandleAddMCP_DryRunExpandReturnsExpandedWithoutPersisting(t *testing.T) {
	gw := newMCPTestGateway(t, "/apps")
	gw.apisByID["rest-1"] = restSourceSpec("rest-1", "org-1", true)

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/apps", 0755))

	body, err := json.Marshal(pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tyk/mcps?dryRun=true&expand=true", bytes.NewReader(body))

	obj, code := gw.handleAddMCP(req, fs)

	require.Equal(t, http.StatusOK, code)
	expanded, ok := obj.(*oas.OAS)
	require.True(t, ok)
	ext := expanded.GetTykMCPServerExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Primitives, 2)
	assert.Equal(t, []string{"create_order", "list_orders"}, mcpPrimitiveNames(ext.Primitives))
	for _, primitive := range ext.Primitives {
		require.NotNil(t, primitive.Allow)
		assert.True(t, *primitive.Allow)
		assert.NotNil(t, primitive.Annotations)
		assert.NotNil(t, primitive.InputSchema)
	}

	entries, err := afero.ReadDir(fs, "/apps")
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Nil(t, gw.getApiSpec("proxy-1"))
}

func TestHandleAddMCP_DryRunExpandRejectsInvalidSourceWithoutPersisting(t *testing.T) {
	gw := newMCPTestGateway(t, "/apps")
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/apps", 0755))

	body, err := json.Marshal(pairedMCPProxyOAS("proxy-1", "org-1", "missing-rest"))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tyk/mcps?dryRun=true&expand=true", bytes.NewReader(body))

	obj, code := gw.handleAddMCP(req, fs)

	require.Equal(t, http.StatusBadRequest, code)
	msg, ok := obj.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, "missing-rest")

	entries, err := afero.ReadDir(fs, "/apps")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestHandleGetMCPWithExpand_ReturnsExpandedCatalogueForSavedProxy(t *testing.T) {
	gw := newMCPTestGateway(t)
	gw.apisByID["rest-1"] = restSourceSpec("rest-1", "org-1", true)
	gw.apisByID["proxy-1"] = pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Allow: boolPtr(true)},
		},
	})

	obj, code := gw.handleGetMCPWithExpand("proxy-1", true)

	require.Equal(t, http.StatusOK, code)
	expanded, ok := obj.(*oas.OAS)
	require.True(t, ok)
	ext := expanded.GetTykMCPServerExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Primitives, 2)

	createOrder := mcpPrimitiveByName(ext.Primitives, "create_order")
	require.NotNil(t, createOrder)
	require.NotNil(t, createOrder.Allow)
	assert.True(t, *createOrder.Allow)

	listOrders := mcpPrimitiveByName(ext.Primitives, "list_orders")
	require.NotNil(t, listOrders)
	require.NotNil(t, listOrders.Allow)
	assert.False(t, *listOrders.Allow)

	storedExt := gw.apisByID["proxy-1"].OAS.GetTykMCPServerExtension()
	require.NotNil(t, storedExt)
	require.Len(t, storedExt.Primitives, 1)
	assert.Equal(t, "create_order", storedExt.Primitives[0].Source.OperationID)
	assert.Nil(t, storedExt.Primitives[0].InputSchema)
}

func TestHandleGetMCPWithExpand_NormalReadReturnsStoredShape(t *testing.T) {
	gw := newMCPTestGateway(t)
	gw.apisByID["rest-1"] = restSourceSpec("rest-1", "org-1", true)
	gw.apisByID["proxy-1"] = pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Allow: boolPtr(true)},
		},
	})

	obj, code := gw.handleGetMCPWithExpand("proxy-1", false)

	require.Equal(t, http.StatusOK, code)
	stored, ok := obj.(*oas.OAS)
	require.True(t, ok)
	ext := stored.GetTykMCPServerExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Primitives, 1)
	assert.Equal(t, "create_order", ext.Primitives[0].Source.OperationID)
	assert.Nil(t, ext.Primitives[0].InputSchema)
}

func TestHandleGetMCPWithExpand_RemoteProxyReturnsStoredShape(t *testing.T) {
	gw := newMCPTestGateway(t)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "remote_tool"}, Name: "remote_tool", Allow: boolPtr(true)},
		},
	})
	proxy.Proxy.TargetURL = "https://remote.example.com/mcp"
	proxy.MarkAsMCP()
	proxy.OAS.GetTykExtension().Upstream.URL = "https://remote.example.com/mcp"
	gw.apisByID["proxy-1"] = proxy

	obj, code := gw.handleGetMCPWithExpand("proxy-1", true)

	require.Equal(t, http.StatusOK, code)
	stored, ok := obj.(*oas.OAS)
	require.True(t, ok)
	ext := stored.GetTykMCPServerExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Primitives, 1)
	assert.Equal(t, "remote_tool", ext.Primitives[0].Name)
	assert.Nil(t, ext.Primitives[0].InputSchema)
}

func TestHandleGetMCPListOAS_IncludesPairedProxy(t *testing.T) {
	t.Parallel()

	pairedProxy := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "proxy-1",
			OrgID: "org-1",
			Name:  "proxy-1",
			IsOAS: true,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/proxy-1/",
				TargetURL:  oas.AdapterLoopURL("rest-1"),
			},
		},
	}
	require.False(t, pairedProxy.IsMCP())
	require.True(t, pairedProxy.IsMCPManaged())

	gw := &Gateway{apisByID: map[string]*APISpec{
		"proxy-1": pairedProxy,
		"rest-1":  restSourceSpec("rest-1", "org-1", true),
	}}

	obj, code := gw.handleGetMCPListOAS()

	require.Equal(t, http.StatusOK, code)
	apisList, ok := obj.([]oas.OAS)
	require.True(t, ok)
	require.Len(t, apisList, 1)
	tykExt := apisList[0].GetTykExtension()
	require.NotNil(t, tykExt)
	assert.Equal(t, "proxy-1", tykExt.Info.ID)
}

func TestHandleAddApiOAS_ValidatesPairedMCPAdapterUpstream(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	gw.SetConfig(config.Config{
		AppPath:    "/",
		HostName:   "localhost",
		ListenPort: 8080,
	})

	body, err := json.Marshal(pairedMCPProxyOAS("proxy-1", "org-1", "missing-rest"))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tyk/apis/oas", bytes.NewReader(body))

	resp, code := gw.handleAddApi(req, afero.NewMemMapFs(), true)

	require.Equal(t, http.StatusBadRequest, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, "missing-rest")
}

func TestHandleMCP_AlignsSourceRESTGatewayTagsToPairedProxy(t *testing.T) {
	cases := []struct {
		name      string
		handler   func(*Gateway, *http.Request, afero.Fs) (interface{}, int)
		method    string
		path      string
		loadProxy bool
	}{
		{
			name: "add",
			handler: func(gw *Gateway, req *http.Request, fs afero.Fs) (interface{}, int) {
				return gw.handleAddMCP(req, fs)
			},
			method: http.MethodPost,
			path:   "/tyk/mcps",
		},
		{
			name: "update",
			handler: func(gw *Gateway, req *http.Request, fs afero.Fs) (interface{}, int) {
				return gw.handleUpdateMCP("proxy-1", req, fs)
			},
			method:    http.MethodPut,
			path:      "/tyk/mcps/proxy-1",
			loadProxy: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+" copies source tags", func(t *testing.T) {
			gw := pairedMCPGatewayForTagAlignment(tc.loadProxy, true)
			fs := afero.NewMemMapFs()
			require.NoError(t, fs.MkdirAll("/apps", 0755))

			body, err := json.Marshal(pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))
			require.NoError(t, err)
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(body))

			obj, code := tc.handler(gw, req, fs)

			require.Equal(t, http.StatusOK, code)
			resp, ok := obj.(apiModifyKeySuccess)
			require.True(t, ok)
			assert.Equal(t, "proxy-1", resp.Key)
			assertWrittenPairedMCPGatewayTags(t, gw, fs, false, []string{"edge-a", "edge-b"})
		})

		t.Run(tc.name+" rejects missing source", func(t *testing.T) {
			gw := pairedMCPGatewayForTagAlignment(tc.loadProxy, false)
			fs := afero.NewMemMapFs()
			require.NoError(t, fs.MkdirAll("/apps", 0755))

			body, err := json.Marshal(pairedMCPProxyOAS("proxy-1", "org-1", "rest-1"))
			require.NoError(t, err)
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(body))

			obj, code := tc.handler(gw, req, fs)

			require.Equal(t, http.StatusBadRequest, code)
			msg, ok := obj.(apiStatusMessage)
			require.True(t, ok)
			assert.Contains(t, msg.Message, "paired REST API rest-1 is not loaded")
		})
	}
}

func pairedMCPGatewayForTagAlignment(loadProxy, loadSource bool) *Gateway {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	gw.SetConfig(config.Config{
		AppPath:    "/apps",
		HostName:   "localhost",
		ListenPort: 8080,
	})
	if loadSource {
		gw.apisByID["rest-1"] = restSourceSpec("rest-1", "org-1", true)
		gw.apisByID["rest-1"].TagsDisabled = false
		gw.apisByID["rest-1"].Tags = []string{"edge-a", "edge-b"}
	}
	if loadProxy {
		gw.apisByID["proxy-1"] = pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	}
	return gw
}

func assertWrittenPairedMCPGatewayTags(t *testing.T, gw *Gateway, fs afero.Fs, tagsDisabled bool, tags []string) {
	t.Helper()

	apiDefBody, err := afero.ReadFile(fs, gw.GetConfig().AppPath+"/proxy-1.json")
	require.NoError(t, err)
	var apiDef apidef.APIDefinition
	require.NoError(t, json.Unmarshal(apiDefBody, &apiDef))
	assert.Equal(t, tagsDisabled, apiDef.TagsDisabled)
	assert.Equal(t, tags, apiDef.Tags)

	oasBody, err := afero.ReadFile(fs, gw.GetConfig().AppPath+"/proxy-1-mcp.json")
	require.NoError(t, err)
	var proxyOAS oas.OAS
	require.NoError(t, json.Unmarshal(oasBody, &proxyOAS))
	require.NotNil(t, proxyOAS.GetTykExtension().Server.GatewayTags)
	assert.Equal(t, !tagsDisabled, proxyOAS.GetTykExtension().Server.GatewayTags.Enabled)
	assert.Equal(t, tags, proxyOAS.GetTykExtension().Server.GatewayTags.Tags)
}

func TestHandleGetMCPListOAS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create multiple MCP Proxies
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

	t.Run("returns only MCP Proxies", func(t *testing.T) {
		obj, code := ts.Gw.handleGetMCPListOAS()

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		assert.Len(t, apisList, 2, "Should return exactly 2 MCP Proxies")
	})

	t.Run("returns empty list when no MCP Proxies exist", func(t *testing.T) {
		// Create a new gateway with no MCP Proxies
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

	// Create test MCP Proxies
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
	appPath := t.TempDir()
	gw := newMCPTestGateway(t, appPath)
	gw.apisByID["mcp-update-test"] = mcpManagedTestSpec("mcp-update-test")

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

	t.Run("updates MCP Proxy successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/mcps/mcp-update-test", strings.NewReader(validMCPUpdate))
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "mcp-update-test"})

		gw.mcpUpdateHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "modified")
		assert.FileExists(t, filepath.Join(appPath, "mcp-update-test.json"))
		assert.FileExists(t, filepath.Join(appPath, "mcp-update-test-mcp.json"))
	})

	t.Run("returns 400 for invalid API ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/mcps/../../../etc/passwd", strings.NewReader(validMCPUpdate))
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "../../../etc/passwd"})

		gw.mcpUpdateHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid API ID")
	})
}

func TestMCPDeleteHandler(t *testing.T) {
	appPath := t.TempDir()
	gw := newMCPTestGateway(t, appPath)
	gw.apisByID["test-api"] = mcpManagedTestSpec("test-api")

	fs := afero.NewOsFs()
	require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, "test-api.json"), []byte("{}"), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, "test-api-mcp.json"), []byte("{}"), 0644))

	t.Run("deletes MCP Proxy successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/tyk/mcps/test-api", nil)
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "test-api"})

		gw.mcpDeleteHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "deleted")
		assert.NoFileExists(t, filepath.Join(appPath, "test-api.json"))
		assert.NoFileExists(t, filepath.Join(appPath, "test-api-mcp.json"))
	})

	t.Run("rejects invalid API ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/tyk/mcps/../../etc/passwd", nil)
		w := httptest.NewRecorder()

		req = mux.SetURLVars(req, map[string]string{"apiID": "../../etc/passwd"})

		gw.mcpDeleteHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid API ID")
	})
}

func TestValidateMCP_PRM(t *testing.T) {
	t.Run("rejects PRM without resource", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

		mcpWithBadPRM := `{
			"openapi": "3.0.3",
			"info": {"title": "Test MCP API", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {
					"name": "test-mcp-api",
					"state": {"active": true}
				},
				"server": {
					"listenPath": {"value": "/test-mcp/"},
					"authentication": {
						"enabled": true,
						"protectedResourceMetadata": {
							"enabled": true,
							"authorizationServers": ["https://auth.example.com"]
						}
					}
				},
				"upstream": {"url": "http://upstream.url"},
				"middleware": {
					"mcpTools": {
						"test-tool": {"allow": {"enabled": true}}
					}
				}
			}
		}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithBadPRM))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "resource is required")
	})

	t.Run("rejects PRM without authorizationServers for MCP", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		})

		handler := newValidateMCPHandler(t, nextHandler)

		mcpWithBadPRM := `{
			"openapi": "3.0.3",
			"info": {"title": "Test MCP API", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {
					"name": "test-mcp-api",
					"state": {"active": true}
				},
				"server": {
					"listenPath": {"value": "/test-mcp/"},
					"authentication": {
						"enabled": true,
						"protectedResourceMetadata": {
							"enabled": true,
							"resource": "https://api.example.com"
						}
					}
				},
				"upstream": {"url": "http://upstream.url"},
				"middleware": {
					"mcpTools": {
						"test-tool": {"allow": {"enabled": true}}
					}
				}
			}
		}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithBadPRM))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, nextCalled, "next handler should not be called")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "authorizationServers")
	})

	t.Run("accepts valid PRM", func(t *testing.T) {
		nextCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := newValidateMCPHandler(t, nextHandler)

		mcpWithGoodPRM := `{
			"openapi": "3.0.3",
			"info": {"title": "Test MCP API", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {
					"name": "test-mcp-api",
					"state": {"active": true}
				},
				"server": {
					"listenPath": {"value": "/test-mcp/"},
					"authentication": {
						"enabled": true,
						"protectedResourceMetadata": {
							"enabled": true,
							"resource": "https://api.example.com",
							"authorizationServers": ["https://auth.example.com"],
							"scopesSupported": ["read", "write"]
						}
					}
				},
				"upstream": {"url": "http://upstream.url"},
				"middleware": {
					"mcpTools": {
						"test-tool": {"allow": {"enabled": true}}
					}
				}
			}
		}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(mcpWithGoodPRM))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
