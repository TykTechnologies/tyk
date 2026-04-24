package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func loadMCPAPI(t *testing.T, ts *Test, mw *oas.Middleware) {
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

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	loaded := ts.Gw.getApiSpec(def.APIID)
	require.NotNil(t, loaded)
	require.True(t, loaded.IsMCP())
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
