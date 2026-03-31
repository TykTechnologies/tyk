package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/opentelemetry/metric/metrictest"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
)

// -- helpers --

func mcpSpec() *APISpec {
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}
}

func mcpSpecWithPrimitives(primitives map[string]string) *APISpec {
	spec := mcpSpec()
	spec.MCPPrimitives = primitives
	spec.JSONRPCRouter = mcp.NewRouter()
	return spec
}

func mcpMiddleware(spec *APISpec) *JSONRPCMiddleware {
	return &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}
}

func postJSONRPC(method string, params map[string]interface{}, id interface{}) *http.Request {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      id,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func mcpMetricDefs() []apimetrics.APIMetricDefinition {
	return []apimetrics.APIMetricDefinition{{
		Name: "test.mcp.requests",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "mcp_method", Label: "mcp_method", Default: ""},
			{Source: "metadata", Key: "mcp_primitive_type", Label: "mcp_primitive_type", Default: ""},
			{Source: "metadata", Key: "mcp_primitive_name", Label: "mcp_primitive_name", Default: ""},
			{Source: "metadata", Key: "mcp_error_code", Label: "mcp_error_code", Default: ""},
		},
	}}
}

// -- ctxSet/ctxGet roundtrips --

func TestCtxSetMCPMethod_Roundtrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPMethod(r, "tools/call")
	assert.Equal(t, "tools/call", ctxGetMCPMethod(r))
}

func TestCtxSetMCPPrimitiveType_Roundtrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPPrimitiveType(r, "tool")
	assert.Equal(t, "tool", ctxGetMCPPrimitiveType(r))
}

func TestCtxSetMCPPrimitiveName_Roundtrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPPrimitiveName(r, "get_weather")
	assert.Equal(t, "get_weather", ctxGetMCPPrimitiveName(r))
}

func TestCtxSetJSONRPCErrorCode_Roundtrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetJSONRPCErrorCode(r, -32601)
	assert.Equal(t, -32601, ctxGetJSONRPCErrorCode(r))
}

func TestCtxGetMCPMethod_EmptyWhenNotSet(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	assert.Equal(t, "", ctxGetMCPMethod(r))
}

func TestCtxGetMCPPrimitiveType_EmptyWhenNotSet(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	assert.Equal(t, "", ctxGetMCPPrimitiveType(r))
}

func TestCtxGetMCPPrimitiveName_EmptyWhenNotSet(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	assert.Equal(t, "", ctxGetMCPPrimitiveName(r))
}

func TestCtxGetJSONRPCErrorCode_ZeroWhenNotSet(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	assert.Equal(t, 0, ctxGetJSONRPCErrorCode(r))
}

func TestCtxSetMCPMethod_OverwritesPreviousValue(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPMethod(r, "resources/read")
	ctxSetMCPMethod(r, "prompts/get")
	assert.Equal(t, "prompts/get", ctxGetMCPMethod(r))
}

// -- primitiveTypeForMethod --

func TestPrimitiveTypeForMethod_ToolsCall(t *testing.T) {
	assert.Equal(t, mcp.PrimitiveTypeTool, primitiveTypeForMethod(mcp.MethodToolsCall))
}

func TestPrimitiveTypeForMethod_ResourcesRead(t *testing.T) {
	assert.Equal(t, mcp.PrimitiveTypeResource, primitiveTypeForMethod(mcp.MethodResourcesRead))
}

func TestPrimitiveTypeForMethod_PromptsGet(t *testing.T) {
	assert.Equal(t, mcp.PrimitiveTypePrompt, primitiveTypeForMethod(mcp.MethodPromptsGet))
}

func TestPrimitiveTypeForMethod_Initialize(t *testing.T) {
	assert.Equal(t, "", primitiveTypeForMethod("initialize"))
}

func TestPrimitiveTypeForMethod_ToolsList(t *testing.T) {
	assert.Equal(t, "", primitiveTypeForMethod("tools/list"))
}

func TestPrimitiveTypeForMethod_ResourcesList(t *testing.T) {
	assert.Equal(t, "", primitiveTypeForMethod("resources/list"))
}

func TestPrimitiveTypeForMethod_PromptsList(t *testing.T) {
	assert.Equal(t, "", primitiveTypeForMethod("prompts/list"))
}

// -- writeJSONRPCError stashes error code --

func TestWriteJSONRPCError_StashesParseError(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()

	m.writeJSONRPCError(w, r, 1, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)

	assert.Equal(t, mcp.JSONRPCParseError, ctxGetJSONRPCErrorCode(r))

	var resp JSONRPCErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, mcp.JSONRPCParseError, resp.Error.Code)
}

func TestWriteJSONRPCError_StashesInvalidRequest(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()

	m.writeJSONRPCError(w, r, 1, mcp.JSONRPCInvalidRequest, mcp.ErrMsgInvalidRequest, nil)

	assert.Equal(t, mcp.JSONRPCInvalidRequest, ctxGetJSONRPCErrorCode(r))
}

func TestWriteJSONRPCError_StashesInvalidParams(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()

	m.writeJSONRPCError(w, r, 1, mcp.JSONRPCInvalidParams, "tool not found", nil)

	assert.Equal(t, mcp.JSONRPCInvalidParams, ctxGetJSONRPCErrorCode(r))
}

func TestWriteJSONRPCError_StashesMethodNotFound(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()

	m.writeJSONRPCError(w, r, 1, mcp.JSONRPCMethodNotFound, "method not available", nil)

	assert.Equal(t, mcp.JSONRPCMethodNotFound, ctxGetJSONRPCErrorCode(r))
}

// -- ProcessRequest MCP context propagation --

func TestProcessRequest_ToolsCall_PropagatesMCPContext(t *testing.T) {
	spec := mcpSpecWithPrimitives(map[string]string{
		"tool:get_weather": mcp.ToolPrefix + "get_weather",
	})
	m := mcpMiddleware(spec)
	r := postJSONRPC("tools/call", map[string]interface{}{
		"name":      "get_weather",
		"arguments": map[string]string{"city": "London"},
	}, 1)
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, "tools/call", ctxGetMCPMethod(r))
	assert.Equal(t, "tool", ctxGetMCPPrimitiveType(r))
	assert.Equal(t, "get_weather", ctxGetMCPPrimitiveName(r))
}

func TestProcessRequest_ResourcesRead_PropagatesMCPContext(t *testing.T) {
	spec := mcpSpecWithPrimitives(map[string]string{
		"resource:file:///data.txt": mcp.ResourcePrefix + "file:///data.txt",
	})
	m := mcpMiddleware(spec)
	r := postJSONRPC("resources/read", map[string]interface{}{
		"uri": "file:///data.txt",
	}, 1)
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, "resources/read", ctxGetMCPMethod(r))
	assert.Equal(t, "resource", ctxGetMCPPrimitiveType(r))
	assert.Equal(t, "file:///data.txt", ctxGetMCPPrimitiveName(r))
}

func TestProcessRequest_PromptsGet_PropagatesMCPContext(t *testing.T) {
	spec := mcpSpecWithPrimitives(map[string]string{
		"prompt:summarize": mcp.PromptPrefix + "summarize",
	})
	m := mcpMiddleware(spec)
	r := postJSONRPC("prompts/get", map[string]interface{}{
		"name": "summarize",
	}, 1)
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, "prompts/get", ctxGetMCPMethod(r))
	assert.Equal(t, "prompt", ctxGetMCPPrimitiveType(r))
	assert.Equal(t, "summarize", ctxGetMCPPrimitiveName(r))
}

func TestProcessRequest_Initialize_NoPrimitiveType(t *testing.T) {
	spec := mcpSpecWithPrimitives(map[string]string{
		"tool:get_weather": mcp.ToolPrefix + "get_weather",
	})
	m := mcpMiddleware(spec)
	r := postJSONRPC("initialize", map[string]interface{}{}, 1)
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, "initialize", ctxGetMCPMethod(r))
	assert.Equal(t, "", ctxGetMCPPrimitiveType(r))
	// routeOperation sets PrimitiveName = method for non-primitive methods
	assert.Equal(t, "initialize", ctxGetMCPPrimitiveName(r))
}

// -- ProcessRequest error paths stash error code --

func TestProcessRequest_InvalidJSON_StashesParseError(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, mcp.JSONRPCParseError, ctxGetJSONRPCErrorCode(r))
}

func TestProcessRequest_MissingVersion_StashesInvalidRequest(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"method":"tools/call","id":1}`)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, mcp.JSONRPCInvalidRequest, ctxGetJSONRPCErrorCode(r))
}

func TestProcessRequest_EmptyMethod_StashesInvalidRequest(t *testing.T) {
	m := mcpMiddleware(mcpSpec())
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"","id":1}`)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, _ := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)

	assert.Equal(t, mcp.JSONRPCInvalidRequest, ctxGetJSONRPCErrorCode(r))
}

// -- NeedsMCP flag detection --

func TestNeedsMCP_FalseWithNilDefinitions(t *testing.T) {
	inst, _ := testMetricInstruments(t, nil)
	assert.False(t, inst.NeedsMCP())
}

func TestNeedsMCP_FalseWithNonMCPMetadata(t *testing.T) {
	defs := []apimetrics.APIMetricDefinition{{
		Name: "test.metric",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "api_id", Label: "api_id"},
		},
	}}
	inst, _ := testMetricInstruments(t, defs)
	assert.False(t, inst.NeedsMCP())
}

func TestNeedsMCP_TrueWithMCPMethodDimension(t *testing.T) {
	defs := []apimetrics.APIMetricDefinition{{
		Name: "test.metric",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "mcp_method", Label: "mcp_method"},
		},
	}}
	inst, _ := testMetricInstruments(t, defs)
	assert.True(t, inst.NeedsMCP())
}

func TestNeedsMCP_TrueWithMCPPrimitiveTypeDimension(t *testing.T) {
	defs := []apimetrics.APIMetricDefinition{{
		Name: "test.metric",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "mcp_primitive_type", Label: "mcp_primitive_type"},
		},
	}}
	inst, _ := testMetricInstruments(t, defs)
	assert.True(t, inst.NeedsMCP())
}

func TestNeedsMCP_TrueWithMCPErrorCodeDimension(t *testing.T) {
	defs := []apimetrics.APIMetricDefinition{{
		Name: "test.metric",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "mcp_error_code", Label: "mcp_error_code"},
		},
	}}
	inst, _ := testMetricInstruments(t, defs)
	assert.True(t, inst.NeedsMCP())
}

func TestNeedsMCP_TrueWithMixedDimensions(t *testing.T) {
	defs := []apimetrics.APIMetricDefinition{{
		Name: "test.metric",
		Type: "counter",
		Dimensions: []apimetrics.DimensionDefinition{
			{Source: "metadata", Key: "api_id", Label: "api_id"},
			{Source: "metadata", Key: "mcp_method", Label: "mcp_method"},
		},
	}}
	tp := metrictest.NewProvider(t)
	inst := otel.NewMetricInstruments(tp, logrus.New())
	inst.SetRegistry(tp, defs)
	assert.True(t, inst.NeedsMCP())
}

// -- RecordMetrics MCP integration --

func TestRecordMetrics_MCPDimensions_AllFieldsPopulated(t *testing.T) {
	inst, tp := testMetricInstruments(t, mcpMetricDefs())
	require.True(t, inst.NeedsMCP())

	bm := &BaseMiddleware{
		Spec: &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "mcp-api"}},
		Gw:   &Gateway{MetricInstruments: inst},
	}

	r := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	ctxSetMCPMethod(r, "tools/call")
	ctxSetMCPPrimitiveType(r, "tool")
	ctxSetMCPPrimitiveName(r, "get_weather")

	bm.RecordMetrics(nil, r, 200, analytics.Latency{Total: 100}, nil)

	m := tp.FindMetric(t, "test.mcp.requests")
	metrictest.AssertSum(t, m, int64(1))
}

func TestRecordMetrics_MCPDimensions_WithErrorCode(t *testing.T) {
	inst, tp := testMetricInstruments(t, mcpMetricDefs())
	bm := &BaseMiddleware{
		Spec: &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "mcp-api"}},
		Gw:   &Gateway{MetricInstruments: inst},
	}

	r := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	ctxSetMCPMethod(r, "tools/call")
	ctxSetMCPPrimitiveType(r, "tool")
	ctxSetMCPPrimitiveName(r, "get_weather")
	ctxSetJSONRPCErrorCode(r, -32601)

	bm.RecordMetrics(nil, r, 200, analytics.Latency{Total: 100}, nil)

	m := tp.FindMetric(t, "test.mcp.requests")
	metrictest.AssertSum(t, m, int64(1))
}

func TestRecordMetrics_MCPDimensions_ResourceRead(t *testing.T) {
	inst, tp := testMetricInstruments(t, mcpMetricDefs())
	bm := &BaseMiddleware{
		Spec: &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "mcp-api"}},
		Gw:   &Gateway{MetricInstruments: inst},
	}

	r := httptest.NewRequest(http.MethodPost, "http://example.com/mcp", nil)
	ctxSetMCPMethod(r, "resources/read")
	ctxSetMCPPrimitiveType(r, "resource")
	ctxSetMCPPrimitiveName(r, "file:///data.txt")

	bm.RecordMetrics(nil, r, 200, analytics.Latency{Total: 100}, nil)

	m := tp.FindMetric(t, "test.mcp.requests")
	metrictest.AssertSum(t, m, int64(1))
}

func TestRecordMetrics_MCPDimensions_NotPopulatedWithoutNeedsMCP(t *testing.T) {
	// No MCP dimensions configured — NeedsMCP is false.
	inst, tp := testMetricInstruments(t, nil)
	require.False(t, inst.NeedsMCP())

	bm := &BaseMiddleware{
		Spec: &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "normal-api"}},
		Gw:   &Gateway{MetricInstruments: inst},
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	// Set MCP values — they should NOT be read when NeedsMCP is false.
	ctxSetMCPMethod(r, "tools/call")
	ctxSetMCPPrimitiveType(r, "tool")
	ctxSetMCPPrimitiveName(r, "dangerous_tool")
	ctxSetJSONRPCErrorCode(r, -32601)

	bm.RecordMetrics(nil, r, 200, analytics.Latency{}, nil)

	// Default tyk.http.requests should still be recorded.
	m := tp.FindMetric(t, "tyk.http.requests")
	metrictest.AssertSum(t, m, int64(1))
}
