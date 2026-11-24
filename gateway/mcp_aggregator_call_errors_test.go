package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPAggregatorPassesJSONRPCErrorsOfAServerErrorThrough(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("create_order")...)
	orders.call = func(*http.Request, map[string]json.RawMessage) (string, int, string) {
		return "", http.StatusInternalServerError, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"db down"}}`
	}
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))

	assert.Equal(t, http.StatusOK, res.status, res.body)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":"call-1","error":{"code":-32603,"message":"db down"}}`, res.body)
}

func TestMCPAggregatorReportsAServerErrorWithoutAJSONRPCErrorAsUnavailable(t *testing.T) {
	for name, body := range map[string]string{
		"plain text":              `internal error`,
		"non JSON-RPC error":      `{"error":"internal error"}`,
		"JSON-RPC without result": `{"jsonrpc":"2.0","id":1}`,
		"gateway JSON-RPC error":  `{"jsonrpc":"2.0","id":1,"error":{"code":-33006,"message":"There was a problem proxying the request","data":{"http_code":500}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			orders := newMCPRoutingUpstream(t, namedTools("create_order")...)
			orders.call = func(*http.Request, map[string]json.RawMessage) (string, int, string) {
				return "", http.StatusInternalServerError, body
			}
			ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

			res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))

			assert.Equal(t, http.StatusServiceUnavailable, res.status, res.body)
			require.NotNil(t, res.rpc.Error, res.body)
			assert.Equal(t, `upstream unavailable: aggregated MCP proxy "orders"`, res.rpc.Error.Message)
		})
	}
}

func TestIsJSONRPCErrorObject(t *testing.T) {
	assert.True(t, isJSONRPCErrorObject(json.RawMessage(`{"code":-32603,"message":"db down"}`)))
	assert.False(t, isJSONRPCErrorObject(nil))
	assert.False(t, isJSONRPCErrorObject(json.RawMessage(`null`)))
	assert.False(t, isJSONRPCErrorObject(json.RawMessage(`"internal error"`)))
	assert.False(t, isJSONRPCErrorObject(json.RawMessage(`{"message":"no code"}`)))
	assert.False(t, isJSONRPCErrorObject(json.RawMessage(`{"code":-32603}`)))
}

func TestIsGatewayJSONRPCError(t *testing.T) {
	assert.True(t, isGatewayJSONRPCError(json.RawMessage(`{"code":-33006,"message":"x","data":{"http_code":502}}`), http.StatusBadGateway))
	assert.False(t, isGatewayJSONRPCError(json.RawMessage(`{"code":-33006,"message":"x","data":{"http_code":502}}`), http.StatusInternalServerError))
	assert.False(t, isGatewayJSONRPCError(json.RawMessage(`{"code":-32603,"message":"db down"}`), http.StatusInternalServerError))
	assert.False(t, isGatewayJSONRPCError(json.RawMessage(`{"code":-32603,"message":"db down","data":"trace"}`), http.StatusInternalServerError))
}
