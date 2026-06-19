package httpctx_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// Verifies: STK-REQ-020, SYS-REQ-108, SW-REQ-028
// STK-REQ-020:nominal:nominal
// STK-REQ-020:boundary:boundary
// SYS-REQ-108:nominal:nominal
// SYS-REQ-108:boundary:boundary
// SW-REQ-028:nominal:nominal
// SW-REQ-028:boundary:boundary
func TestJSONRPCRequest_SetAndGet(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)

	assert.Nil(t, httpctx.GetJSONRPCRequest(req))

	data := &httpctx.JSONRPCRequestData{
		Method:    "tools/call",
		Params:    json.RawMessage(`{"name":"weather.getForecast"}`),
		ID:        float64(7),
		VEMPath:   "/mcp-tool:weather.getForecast",
		Primitive: "weather.getForecast",
		VEMChain:  []string{"/json-rpc-method:tools/call", "/mcp-tool:weather.getForecast"},
	}

	httpctx.SetJSONRPCRequest(req, data)

	assert.Same(t, data, httpctx.GetJSONRPCRequest(req))
}

// Verifies: STK-REQ-020, SYS-REQ-108, SW-REQ-028
// STK-REQ-020:nominal:nominal
// STK-REQ-020:boundary:boundary
// SYS-REQ-108:nominal:nominal
// SYS-REQ-108:boundary:boundary
// SW-REQ-028:nominal:nominal
// SW-REQ-028:boundary:boundary
func TestJsonRPCRoutingFlag(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)

	assert.False(t, httpctx.IsJsonRPCRouting(req))

	httpctx.SetJsonRPCRouting(req, true)
	assert.True(t, httpctx.IsJsonRPCRouting(req))

	httpctx.SetJsonRPCRouting(req, false)
	assert.False(t, httpctx.IsJsonRPCRouting(req))
}
