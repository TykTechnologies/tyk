package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestMCPVEMContinuationMiddleware_Name(t *testing.T) {
	mw := &MCPVEMContinuationMiddleware{
		BaseMiddleware: &BaseMiddleware{},
	}
	assert.Equal(t, "MCPVEMContinuationMiddleware", mw.Name())
}

func TestMCPVEMContinuationMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     *APISpec
		expected bool
	}{
		{
			name: "MCP API with JSON-RPC 2.0",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: apidef.AppProtocolMCP,
					JsonRpcVersion:      apidef.JsonRPC20,
				},
			},
			expected: true,
		},
		{
			name: "MCP API without JSON-RPC version",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: apidef.AppProtocolMCP,
				},
			},
			expected: false,
		},
		{
			name: "Non-MCP API",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: "",
				},
			},
			expected: false,
		},
		{
			name: "HTTP API",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: "http",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &MCPVEMContinuationMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: tt.spec,
				},
			}
			assert.Equal(t, tt.expected, mw.EnabledForSpec())
		})
	}
}

func TestMCPVEMContinuationMiddleware_ProcessRequest(t *testing.T) {
	tests := []struct {
		name               string
		initialState       *httpctx.JSONRPCRoutingState
		expectedHTTPStatus int
		expectsRedirect    bool
		expectedNextVEM    string
	}{
		{
			name:               "no routing state - passthrough",
			initialState:       nil,
			expectedHTTPStatus: http.StatusOK,
			expectsRedirect:    false,
		},
		{
			name: "NextVEM set - route to next",
			initialState: &httpctx.JSONRPCRoutingState{
				Method:       "tools/call",
				NextVEM:      "/mcp-tool:weather.getForecast",
				OriginalPath: "/prct",
				VEMChain:     []string{jsonrpc.MethodVEMPrefix + "tools/call", mcp.ToolPrefix + "weather.getForecast"},
				VisitedVEMs:  []string{},
			},
			expectedHTTPStatus: http.StatusOK,
			expectsRedirect:    true,
			expectedNextVEM:    "",
		},
		{
			name: "NextVEM empty - complete routing",
			initialState: &httpctx.JSONRPCRoutingState{
				Method:       "tools/call",
				NextVEM:      "",
				OriginalPath: "/mcp",
				VEMChain:     []string{jsonrpc.MethodVEMPrefix + "tools/call", mcp.ToolPrefix + "weather.getForecast"},
				VisitedVEMs:  []string{jsonrpc.MethodVEMPrefix + "tools/call"},
			},
			expectedHTTPStatus: http.StatusOK,
			expectsRedirect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &MCPVEMContinuationMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition: &apidef.APIDefinition{
							ApplicationProtocol: apidef.AppProtocolMCP,
							JsonRpcVersion:      apidef.JsonRPC20,
						},
					},
				},
			}

			// Set initial URL path based on test case
			requestPath := jsonrpc.MethodVEMPrefix + "tools/call"
			if tt.initialState != nil && tt.initialState.NextVEM == "" {
				// For complete routing test, start at the final VEM path
				requestPath = "/mcp-tool:weather.getForecast"
			}
			r := httptest.NewRequest("POST", requestPath+"?check_limits=true", nil)
			w := httptest.NewRecorder()

			if tt.initialState != nil {
				httpctx.SetJSONRPCRoutingState(r, tt.initialState)
			}

			err, status := mw.ProcessRequest(w, r, nil)

			// Check HTTP status
			assert.Nil(t, err)
			assert.Equal(t, tt.expectedHTTPStatus, status)

			// Check routing state updates
			if tt.initialState != nil {
				finalState := httpctx.GetJSONRPCRoutingState(r)
				require.NotNil(t, finalState)
				assert.Equal(t, tt.expectedNextVEM, finalState.NextVEM)

				// Check VEM was recorded (use the original request path, not the restored path)
				if !tt.expectsRedirect && tt.initialState.NextVEM == "" {
					// When routing is complete, check the VEM path was recorded before restoration
					assert.Contains(t, finalState.VisitedVEMs, "/mcp-tool:weather.getForecast")
				} else if r.URL.Path != tt.initialState.OriginalPath {
					// During routing, check current VEM was recorded
					assert.Contains(t, finalState.VisitedVEMs, requestPath)
				}
			}

			// Check redirect URL
			if tt.expectsRedirect {
				redirectURL := ctxGetURLRewriteTarget(r)
				require.NotNil(t, redirectURL)
				assert.Equal(t, "tyk", redirectURL.Scheme)
				assert.Equal(t, "self", redirectURL.Host)
				assert.Equal(t, "/mcp-tool:weather.getForecast", redirectURL.Path)
			} else {
				assert.Nil(t, ctxGetURLRewriteTarget(r))

				// When routing is complete, verify original path is restored
				if tt.initialState != nil && tt.initialState.NextVEM == "" {
					assert.Equal(t, tt.initialState.OriginalPath, r.URL.Path, "Original path should be restored when routing is complete")
					assert.Empty(t, r.URL.RawQuery, "Query parameters should be cleared when routing is complete")
				}
			}
		})
	}
}
