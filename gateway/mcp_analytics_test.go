package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func loadMCPAPI(t *testing.T, ts *Test, mw *oas.Middleware, opts ...func(*apidef.APIDefinition)) *APISpec {
	t.Helper()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Server.ListenPath = oas.ListenPath{Value: "/mcp", Strip: false}
	tykExt.Middleware = mw
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.DoNotTrack = false
	def.Proxy.ListenPath = "/mcp"
	def.MarkAsMCP()
	for _, opt := range opts {
		opt(&def)
	}

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	loaded := ts.Gw.getApiSpec(def.APIID)
	require.NotNil(t, loaded)
	require.True(t, loaded.IsMCP())
	return loaded
}

func captureAnalytics(ts *Test) *atomic.Pointer[analytics.AnalyticsRecord] {
	var captured atomic.Pointer[analytics.AnalyticsRecord]
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		clone := *record
		captured.Store(&clone)
	}
	return &captured
}

func collectAnalytics(ts *Test) func() []analytics.AnalyticsRecord {
	var mu sync.Mutex
	var records []analytics.AnalyticsRecord
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, *record)
	}
	return func() []analytics.AnalyticsRecord {
		mu.Lock()
		defer mu.Unlock()
		drained := records
		records = nil
		return drained
	}
}

func mcpCall(method string, params map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
}

func TestMCPAnalytics_RefusalsRecordedOnce(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	allowed := &oas.MCPPrimitive{Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}}
	spec := loadMCPAPI(t, ts, &oas.Middleware{
		McpTools:     oas.MCPPrimitives{"get-weather": allowed, "get-forecast": allowed},
		McpResources: oas.MCPPrimitives{"file:///secret.txt": allowed},
		McpPrompts:   oas.MCPPrimitives{"summarize": allowed},
	}, func(def *apidef.APIDefinition) {
		def.UseKeylessAccess = false
	})
	drain := collectAnalytics(ts)

	mcpKey := func(customize func(*user.SessionState, *user.AccessDefinition)) map[string]string {
		key := CreateSession(ts.Gw, func(session *user.SessionState) {
			access := user.AccessDefinition{APIID: spec.APIID, Versions: []string{"Default"}}
			customize(session, &access)
			session.AccessRights = map[string]user.AccessDefinition{spec.APIID: access}
		})
		return map[string]string{header.Authorization: key}
	}
	restricted := mcpKey(func(_ *user.SessionState, access *user.AccessDefinition) {
		access.MCPAccessRights = user.MCPAccessRights{
			Tools:     user.AccessControlRules{Allowed: []string{"get-weather"}},
			Resources: user.AccessControlRules{Blocked: []string{"file:///secret.txt"}},
			Prompts:   user.AccessControlRules{Blocked: []string{"summarize"}},
		}
		access.JSONRPCMethodsAccessRights = user.AccessControlRules{Blocked: []string{mcp.MethodToolsList}}
	})
	rateLimited := mcpKey(func(session *user.SessionState, _ *user.AccessDefinition) {
		session.Rate, session.Allowance, session.Per = 1, 1, 60
	})
	quotaLimited := mcpKey(func(session *user.SessionState, _ *user.AccessDefinition) {
		session.QuotaMax, session.QuotaRemaining = 1, 1
	})
	getWeather := mcpCall(mcp.MethodToolsCall, map[string]any{"name": "get-weather"})

	tests := []struct {
		name          string
		method        string
		headers       map[string]string
		body          any
		exhaust       bool
		code          int
		rpcMethod     string
		primitiveType string
		primitiveName string
		rpcCode       int64
	}{
		{
			name: "missing credential", body: getWeather, code: http.StatusUnauthorized,
			rpcMethod: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "get-weather", rpcCode: jsonrpcerrors.CodeAuthRequired,
		},
		{
			name: "unknown credential", headers: map[string]string{header.Authorization: "unknown"}, body: getWeather, code: http.StatusForbidden,
			rpcMethod: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "get-weather", rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "tool outside mcp_access_rights", headers: restricted, body: mcpCall(mcp.MethodToolsCall, map[string]any{"name": "get-forecast"}), code: http.StatusForbidden,
			rpcMethod: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "get-forecast", rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "resource blocked by mcp_access_rights", headers: restricted, body: mcpCall(mcp.MethodResourcesRead, map[string]any{"uri": "file:///secret.txt"}), code: http.StatusForbidden,
			rpcMethod: mcp.MethodResourcesRead, primitiveType: mcp.PrimitiveTypeResource, primitiveName: "file:///secret.txt", rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "prompt blocked by mcp_access_rights", headers: restricted, body: mcpCall(mcp.MethodPromptsGet, map[string]any{"name": "summarize"}), code: http.StatusForbidden,
			rpcMethod: mcp.MethodPromptsGet, primitiveType: mcp.PrimitiveTypePrompt, primitiveName: "summarize", rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "method blocked by json_rpc_methods_access_rights", headers: restricted, body: mcpCall(mcp.MethodToolsList, map[string]any{}), code: http.StatusForbidden,
			rpcMethod: mcp.MethodToolsList, rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "rate limit exceeded", headers: rateLimited, body: getWeather, exhaust: true, code: http.StatusTooManyRequests,
			rpcMethod: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "get-weather", rpcCode: jsonrpcerrors.CodeRateLimitExceeded,
		},
		{
			name: "quota exceeded", headers: quotaLimited, body: getWeather, exhaust: true, code: http.StatusForbidden,
			rpcMethod: mcp.MethodToolsCall, primitiveType: mcp.PrimitiveTypeTool, primitiveName: "get-weather", rpcCode: jsonrpcerrors.CodeAccessDenied,
		},
		{
			name: "malformed JSON-RPC body", headers: map[string]string{header.ContentType: header.ApplicationJSON}, body: `{"jsonrpc":`, code: http.StatusBadRequest,
			rpcCode: mcp.JSONRPCParseError,
		},
		{
			name: "non-JSON content type", headers: map[string]string{header.ContentType: "text/plain"}, body: `{}`, code: http.StatusBadRequest,
			rpcCode: mcp.JSONRPCInvalidRequest,
		},
		{
			name: "untrusted Origin", headers: map[string]string{"Origin": "https://untrusted.example"}, body: getWeather, code: http.StatusForbidden,
		},
		{
			name: "unsupported HTTP method", method: http.MethodGet, headers: map[string]string{mcp.HeaderProtocolVersion: mcp.ModernProtocolVersion}, code: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := test.TestCase{Method: http.MethodPost, Path: "/mcp", Headers: tc.headers, Data: tc.body}
			if tc.method != "" {
				request.Method = tc.method
			}
			if tc.exhaust {
				exhaust := request
				exhaust.Code = http.StatusOK
				_, _ = ts.Run(t, exhaust)
			}
			drain()

			request.Code = tc.code
			_, _ = ts.Run(t, request)

			records := drain()
			require.Len(t, records, 1, "every refused MCP request must produce exactly one analytics record")
			rec := records[0]
			assert.Equal(t, tc.code, rec.ResponseCode)
			assert.True(t, rec.MCPStats.IsMCP)
			assert.Equal(t, tc.rpcMethod, rec.MCPStats.JSONRPCMethod)
			assert.Equal(t, tc.primitiveType, rec.MCPStats.PrimitiveType)
			assert.Equal(t, tc.primitiveName, rec.MCPStats.PrimitiveName)
			assert.Equal(t, tc.rpcCode, rec.MCPStats.JSONRPCErrorCode)
		})
	}
}

func TestMCPAnalytics_ToolsCall(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadMCPAPI(t, ts, &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get_weather": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	})
	captured := captureAnalytics(ts)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params":  map[string]any{"name": "get_weather", "arguments": map[string]string{"city": "London"}},
			"id":      1,
		},
		Code: http.StatusOK,
	})

	rec := captured.Load()
	require.NotNil(t, rec, "analytics record should be captured")
	assert.True(t, rec.MCPStats.IsMCP)
	assert.Equal(t, "tools/call", rec.MCPStats.JSONRPCMethod)
	assert.Equal(t, "tool", rec.MCPStats.PrimitiveType)
	assert.Equal(t, "get_weather", rec.MCPStats.PrimitiveName)
}

func TestMCPAnalytics_ResourcesRead(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadMCPAPI(t, ts, &oas.Middleware{
		McpResources: oas.MCPPrimitives{
			"file:///data.txt": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	})
	captured := captureAnalytics(ts)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "resources/read",
			"params":  map[string]any{"uri": "file:///data.txt"},
			"id":      1,
		},
		Code: http.StatusOK,
	})

	rec := captured.Load()
	require.NotNil(t, rec, "analytics record should be captured")
	assert.True(t, rec.MCPStats.IsMCP)
	assert.Equal(t, "resources/read", rec.MCPStats.JSONRPCMethod)
	assert.Equal(t, "resource", rec.MCPStats.PrimitiveType)
	assert.Equal(t, "file:///data.txt", rec.MCPStats.PrimitiveName)
}

func TestMCPAnalytics_PromptsGet(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadMCPAPI(t, ts, &oas.Middleware{
		McpPrompts: oas.MCPPrimitives{
			"summarize": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	})
	captured := captureAnalytics(ts)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "prompts/get",
			"params":  map[string]any{"name": "summarize"},
			"id":      1,
		},
		Code: http.StatusOK,
	})

	rec := captured.Load()
	require.NotNil(t, rec, "analytics record should be captured")
	assert.True(t, rec.MCPStats.IsMCP)
	assert.Equal(t, "prompts/get", rec.MCPStats.JSONRPCMethod)
	assert.Equal(t, "prompt", rec.MCPStats.PrimitiveType)
	assert.Equal(t, "summarize", rec.MCPStats.PrimitiveName)
}

func TestMCPAnalytics_Initialize_NoPrimitiveFields(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadMCPAPI(t, ts, &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get_weather": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	})
	captured := captureAnalytics(ts)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "initialize",
			"params":  map[string]any{},
			"id":      1,
		},
		Code: http.StatusOK,
	})

	rec := captured.Load()
	require.NotNil(t, rec, "analytics record should be captured")
	assert.True(t, rec.MCPStats.IsMCP)
	assert.Equal(t, "initialize", rec.MCPStats.JSONRPCMethod)
	assert.Empty(t, rec.MCPStats.PrimitiveType)
}

func TestMCPAnalytics_ErrorPath_RecordsMCPStats(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Server.ListenPath = oas.ListenPath{Value: "/mcp", Strip: false}
	tykExt.Upstream.URL = "http://localhost:66666"
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get_weather": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.DoNotTrack = false
	def.Proxy.ListenPath = "/mcp"
	def.Proxy.TargetURL = "http://localhost:66666"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params":  map[string]any{"name": "get_weather", "arguments": map[string]string{"city": "London"}},
			"id":      1,
		},
		Code: http.StatusInternalServerError,
	})

	ts.Gw.Analytics.Flush()
	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1)

	var rec analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &rec)
	require.NoError(t, err)

	assert.True(t, rec.MCPStats.IsMCP)
	assert.Equal(t, "tools/call", rec.MCPStats.JSONRPCMethod)
	assert.Equal(t, "tool", rec.MCPStats.PrimitiveType)
	assert.Equal(t, "get_weather", rec.MCPStats.PrimitiveName)
}

func TestRecordMCPDetails_TagsRequestWithoutJSONRPCState(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := &analytics.AnalyticsRecord{}

	recordMCPDetails(rec, r)

	assert.True(t, rec.MCPStats.IsMCP)
}

func TestMCPAnalytics_NonMCP_NoMCPStats(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
	})
	captured := captureAnalytics(ts)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodGet,
		Path:   "/",
		Code:   http.StatusOK,
	})

	rec := captured.Load()
	require.NotNil(t, rec, "analytics record should be captured")
	assert.False(t, rec.MCPStats.IsMCP)
	assert.Empty(t, rec.MCPStats.JSONRPCMethod)
	assert.Empty(t, rec.MCPStats.PrimitiveType)
	assert.Empty(t, rec.MCPStats.PrimitiveName)
}

func TestMCPAnalytics_RecordHitCount(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	loadMCPAPI(t, ts, &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get_weather": &oas.MCPPrimitive{
				Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}},
			},
		},
	})

	var count atomic.Int32
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(_ *analytics.AnalyticsRecord) {
		count.Add(1)
	}

	tc := test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp",
		Data: map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params":  map[string]any{"name": "get_weather", "arguments": map[string]string{"city": "London"}},
			"id":      1,
		},
		Code: http.StatusOK,
	}

	for range 3 {
		_, _ = ts.Run(t, tc)
	}

	assert.Equal(t, int32(3), count.Load(), "each MCP request should produce exactly one analytics record")
}

func TestMCPAnalytics_RejectedEnvelopeRetainsDeclaration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	loadMCPAPI(t, ts, &oas.Middleware{})
	captured := captureAnalytics(ts)
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost, Path: "/mcp", Code: http.StatusBadRequest,
		Headers: map[string]string{"MCP-Protocol-Version": "2026-07-28"},
		Data:    `{"jsonrpc":"wrong","id":9007199254740993,"method":"server/discover"}`,
	})
	rec := captured.Load()
	require.NotNil(t, rec)
	assert.Equal(t, "2026-07-28", rec.MCPStats.DeclaredProtocolVersion)
	assert.Equal(t, "header", rec.MCPStats.ProtocolVersionSource)
	assert.Equal(t, "server/discover", rec.MCPStats.JSONRPCMethod)
	assert.Equal(t, "discovery", rec.MCPStats.PrimitiveType)
	assert.EqualValues(t, -32600, rec.MCPStats.JSONRPCErrorCode)
}
