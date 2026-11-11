package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

func TestMCPAggregatorPolicyRateLimitsAToolByItsAggregatedName(t *testing.T) {
	ts, orders, _ := startMCPAggregatorSecurityTest(t)
	key := companyToolsPolicyKey(t, ts, user.AccessDefinition{MCPPrimitives: []user.MCPPrimitiveLimit{
		{Type: mcp.PrimitiveTypeTool, Name: "orders__create_order", Limit: user.RateLimit{Rate: 5, Per: 60}},
	}})

	for i := 1; i <= 5; i++ {
		res := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
	}
	sixth := postMCPToolsCall(t, ts, key, toolCallParams("orders__create_order", `{}`, ""))
	other := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

	assert.Equal(t, http.StatusTooManyRequests, sixth.status, sixth.body)
	require.NotNil(t, sixth.rpc.Error, sixth.body)
	assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, sixth.rpc.Error.Code)
	assert.Equal(t, http.StatusOK, other.status, "the limit applies to orders__create_order only: %s", other.body)
	assert.Len(t, orders.observed(mcp.MethodToolsCall), 6, "the sixth create_order never reaches the proxy")
}

// TestMCPAggregatorRateLimitsStackAcrossChains checks that the aggregator's
// and the aggregated proxy's API-level limits apply independently, each
// counting a call once.
func TestMCPAggregatorRateLimitsStackAcrossChains(t *testing.T) {
	start := func(t *testing.T, aggregatorRate, ordersRate float64) (*Test, string, *mcpRoutingUpstream) {
		t.Helper()
		orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
		orders.call = answering(`{"content":[]}`)
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		ts.Gw.LoadAPI(
			withAPIRateLimit(remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL), ordersRate, 60),
			remoteMCPProxyRuntimeSpec("github-mcp", newMCPRoutingUpstream(t, namedTools("list_issues")...).URL),
			withAPIRateLimit(companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")), aggregatorRate, 60),
		)
		return ts, companyToolsKey(t, ts), orders
	}
	callTen := func(t *testing.T, ts *Test, key string) {
		t.Helper()
		for i := 1; i <= 10; i++ {
			res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))
			require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
			require.Nil(t, res.rpc.Error, "call %d: %s", i, res.body)
		}
	}

	t.Run("the orders chain limits the 11th call", func(t *testing.T) {
		ts, key, orders := start(t, 100, 10)
		callTen(t, ts, key)

		eleventh := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

		assert.Equal(t, http.StatusOK, eleventh.status, "the proxy's JSON-RPC error is answered with HTTP 200: %s", eleventh.body)
		require.NotNil(t, eleventh.rpc.Error, eleventh.body)
		assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, eleventh.rpc.Error.Code)
		assert.Equal(t, "API Rate Limit Exceeded", eleventh.rpc.Error.Message)
		assert.JSONEq(t, `{"jsonrpc":"2.0","id":"call-1","error":{"code":-33004,"message":"API Rate Limit Exceeded","data":{"http_code":429}}}`, eleventh.body)
		assert.Len(t, orders.observed(mcp.MethodToolsCall), 10)
	})
	t.Run("the aggregator limits the 11th call", func(t *testing.T) {
		ts, key, orders := start(t, 10, 100)
		callTen(t, ts, key)

		eleventh := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

		assert.Equal(t, http.StatusTooManyRequests, eleventh.status, eleventh.body)
		require.NotNil(t, eleventh.rpc.Error, eleventh.body)
		assert.Equal(t, jsonrpcerrors.CodeModernRateLimitExceeded, eleventh.rpc.Error.Code)
		assert.Len(t, orders.observed(mcp.MethodToolsCall), 10)
	})
}

func TestMCPAggregatorIgnoresConsumerQuotasOfTheAggregatedProxy(t *testing.T) {
	ts, orders, _ := startMCPAggregatorSecurityTest(t)
	_, otherKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.QuotaMax, s.QuotaRemaining, s.QuotaRenewalRate = 5, 5, 3600
		s.AccessRights = map[string]user.AccessDefinition{"orders-mcp": {APIID: "orders-mcp", APIName: "orders-mcp"}}
	})
	key := companyToolsKey(t, ts)

	for i := 1; i <= 7; i++ {
		res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, "call %d: %s", i, res.body)
		require.Nil(t, res.rpc.Error, "call %d: %s", i, res.body)
	}
	for i := 1; i <= 5; i++ {
		res := postMCPToolsCallTo(t, ts, "/orders-mcp/", otherKey, toolCallParams("list_orders", `{}`, ""))
		require.Equal(t, http.StatusOK, res.status, "direct call %d: %s", i, res.body)
	}
	sixth := postMCPToolsCallTo(t, ts, "/orders-mcp/", otherKey, toolCallParams("list_orders", `{}`, ""))

	assert.Equal(t, http.StatusForbidden, sixth.status, "the other key's own quota still holds: %s", sixth.body)
	require.NotNil(t, sixth.rpc.Error, sixth.body)
	assert.Equal(t, jsonrpcerrors.CodeModernQuotaExceeded, sixth.rpc.Error.Code)
	assert.Len(t, orders.observed(mcp.MethodToolsCall), 12)
}
