package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// buildTestAdapterSpec builds a minimal synthetic adapter APISpec by
// hand — no loadApps, no chain, just enough for the unit tests in this
// file to exercise the inline handler and the loop-auth-bypass logic.
func buildTestAdapterSpec() *APISpec {
	def := &apidef.APIDefinition{
		APIID: oas.AdapterAPIID("rest-1"),
		Name:  "test [MCP adapter]",
		OrgID: "org-1",
	}
	def.MarkAsMCP()
	def.Internal = true

	return &APISpec{
		APIDefinition:         def,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		DerivedTools: []oas.DerivedTool{
			{
				Name:           "getOrder",
				Description:    "fetch an order by id",
				Method:         http.MethodGet,
				PathTemplate:   "/orders/{id}",
				ParamLocations: map[string]string{"id": "path"},
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id": map[string]any{"type": "string"},
					},
					"required": []string{"id"},
				},
			},
		},
	}
}

func TestAdapterInline_Initialize(t *testing.T) {
	t.Parallel()

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: buildTestAdapterSpec()}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	ok := m.handleAdapterInline(w, r, &JSONRPCRequest{
		JSONRPC: apidef.JsonRPC20,
		Method:  mcpMethodInitialize,
		ID:      1,
	})
	require.True(t, ok)
	assert.Equal(t, http.StatusOK, w.Code)

	var env map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	res, ok := env["result"].(map[string]any)
	require.True(t, ok, "result must be an object")
	assert.Equal(t, mcpAdapterProtocolVersion, res["protocolVersion"])
}

func TestAdapterInline_ToolsList(t *testing.T) {
	t.Parallel()

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: buildTestAdapterSpec()}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	ok := m.handleAdapterInline(w, r, &JSONRPCRequest{
		JSONRPC: apidef.JsonRPC20,
		Method:  "tools/list",
		ID:      2,
	})
	require.True(t, ok)

	var env map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	res := env["result"].(map[string]any)
	tools := res["tools"].([]any)
	require.Len(t, tools, 1)
	first := tools[0].(map[string]any)
	assert.Equal(t, "getOrder", first["name"])
}

func TestAdapterInline_PingEmpty(t *testing.T) {
	t.Parallel()

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: buildTestAdapterSpec()}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	ok := m.handleAdapterInline(w, r, &JSONRPCRequest{
		JSONRPC: apidef.JsonRPC20,
		Method:  mcpMethodPing,
		ID:      3,
	})
	require.True(t, ok)

	var env map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	res := env["result"].(map[string]any)
	assert.Empty(t, res)
}

func TestAdapterInline_NotAdapterFallsThrough(t *testing.T) {
	t.Parallel()

	def := &apidef.APIDefinition{APIID: "regular", OrgID: "org-1"}
	def.MarkAsMCP()
	spec := &APISpec{APIDefinition: def} // IsSyntheticMCPAdapter false

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	ok := m.handleAdapterInline(w, r, &JSONRPCRequest{Method: mcpMethodInitialize})
	assert.False(t, ok, "non-adapter specs must not be handled inline")
	assert.Empty(t, w.Body.String())
}

func TestBuildAdapterUpstreamRequest_PathQueryBody(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	spec := buildTestAdapterSpec()
	// Augment with one body-field tool to exercise body.<field> expansion.
	spec.DerivedTools = append(spec.DerivedTools, oas.DerivedTool{
		Name:         "createOrder",
		Method:       http.MethodPost,
		PathTemplate: "/orders",
		ParamLocations: map[string]string{
			"sku":     "body.sku",
			"qty":     "body.qty",
			"trace":   "header",
			"verbose": "query",
		},
	})

	tool := findDerivedTool(spec.DerivedTools, "createOrder")
	require.NotNil(t, tool)

	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	args := map[string]any{
		"sku":     "ABC",
		"qty":     5,
		"trace":   "trace-id-1",
		"verbose": "true",
	}
	req, err := gw.buildAdapterUpstreamRequest(parent, spec, tool, args)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "/orders", req.URL.Path)
	assert.Equal(t, "true", req.URL.Query().Get("verbose"))
	assert.Equal(t, "trace-id-1", req.Header.Get("trace"))
	assert.Equal(t, contentTypeJSON, req.Header.Get(headerContentType))

	bodyBytes, err := readAllNoClose(req)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &body))
	assert.Equal(t, "ABC", body["sku"])
	assert.EqualValues(t, 5, body["qty"])
}

func TestBuildAdapterUpstreamRequest_PathParamSubstitution(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	spec := buildTestAdapterSpec()
	tool := findDerivedTool(spec.DerivedTools, "getOrder")
	require.NotNil(t, tool)

	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	req, err := gw.buildAdapterUpstreamRequest(parent, spec, tool, map[string]any{"id": "42"})
	require.NoError(t, err)
	assert.Equal(t, "/orders/42", req.URL.Path)
	assert.Equal(t, http.MethodGet, req.Method)
}

func TestBuildAdapterUpstreamRequest_MissingPathParam(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	spec := buildTestAdapterSpec()
	tool := findDerivedTool(spec.DerivedTools, "getOrder")

	parent := httptest.NewRequest(http.MethodPost, "/mcp/", nil)
	_, err := gw.buildAdapterUpstreamRequest(parent, spec, tool, map[string]any{})
	require.Error(t, err)
}

func TestMCPLoopAuthBypass_NoFlagPassesThrough(t *testing.T) {
	t.Parallel()

	gw := &Gateway{apisMu: sync.RWMutex{}, mcpPairing: map[string]string{}}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1"}}
	spec.MCPExposure.Enabled = true

	mw := &MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}

	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	w := httptest.NewRecorder()
	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPLoopAuthBypass_MismatchedFlagReturns403(t *testing.T) {
	t.Parallel()

	gw := &Gateway{apisMu: sync.RWMutex{}, mcpPairing: map[string]string{"rest-1": "proxy-real"}}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1"}}
	spec.MCPExposure.Enabled = true

	mw := &MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}

	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	httpctx.SetMCPLoopFromPairedProxy(r, &httpctx.MCPLoopTrust{
		ProxyAPIID:   "proxy-forged",
		RESTAPIID:    "rest-1",
		AdapterAPIID: oas.AdapterAPIID("rest-1"),
	})

	w := httptest.NewRecorder()
	err, code := mw.ProcessRequest(w, r, nil)
	assert.Error(t, err)
	assert.Equal(t, http.StatusForbidden, code)
}

func TestMCPLoopAuthBypass_MatchedFlagInstallsSession(t *testing.T) {
	t.Parallel()

	gw := &Gateway{apisMu: sync.RWMutex{}, mcpPairing: map[string]string{"rest-1": "proxy-1"}}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1"}}
	spec.MCPExposure.Enabled = true

	mw := &MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}

	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	httpctx.SetMCPLoopFromPairedProxy(r, &httpctx.MCPLoopTrust{
		ProxyAPIID:   "proxy-1",
		RESTAPIID:    "rest-1",
		AdapterAPIID: oas.AdapterAPIID("rest-1"),
	})

	w := httptest.NewRecorder()
	err, code := mw.ProcessRequest(w, r, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Session must be installed.
	session := ctxGetSession(r)
	require.NotNil(t, session)
	assert.Equal(t, "mcp-loop:proxy-1", session.KeyID)
}

func TestMCPLoopAuthBypass_EnabledForSpec(t *testing.T) {
	t.Parallel()

	exposed := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest"}}
	exposed.MCPExposure.Enabled = true
	plain := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest2"}}

	assert.True(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: exposed}}).EnabledForSpec())
	assert.False(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: plain}}).EnabledForSpec())
}

// readAllNoClose drains the request body without consuming the closer
// (so it can be re-read in production code). For tests we just need the
// bytes.
func readAllNoClose(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	_, err := buf.ReadFrom(req.Body)
	return buf.Bytes(), err
}
