package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
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
				VEMChain:     []string{"/json-rpc-method:tools/call", "/mcp-tool:weather.getForecast"},
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
				OriginalPath: "/prct",
				VEMChain:     []string{"/json-rpc-method:tools/call", "/mcp-tool:weather.getForecast"},
				VisitedVEMs:  []string{"/json-rpc-method:tools/call"},
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

			r := httptest.NewRequest("POST", "/json-rpc-method:tools/call", nil)
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

				// Check VEM was recorded
				assert.Contains(t, finalState.VisitedVEMs, r.URL.Path)
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
			}
		})
	}
}
