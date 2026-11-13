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

// startMCPAggregatorSecurityTest loads company-tools over orders-mcp
// (list_orders, create_order) and github-mcp (list_issues, create_issue),
// both remote MCP proxies whose tools answer every call.
func startMCPAggregatorSecurityTest(t *testing.T) (ts *Test, orders, github *mcpRoutingUpstream) {
	t.Helper()
	orders = newMCPRoutingUpstream(t, namedTools("list_orders", "create_order")...)
	orders.call = answering(`{"content":[]}`)
	github = newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue")...)
	github.call = answering(`{"content":[]}`)
	ts = startExactRateLimitTest(t)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	return ts, orders, github
}

// companyToolsPolicyKey returns a key whose only access to company-tools
// comes from a policy granting it with the given access definition.
func companyToolsPolicyKey(t *testing.T, ts *Test, def user.AccessDefinition) string {
	t.Helper()
	def.APIID, def.APIName = "company-tools", "company-tools"
	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = mcpAggregatorRuntimeOrg
		p.Rate, p.Per = 1000, 1
		p.QuotaMax = -1
		p.AccessRights = map[string]user.AccessDefinition{"company-tools": def}
	})
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.ApplyPolicies = []string{policyID}
	})
	require.NotEmpty(t, key)
	return key
}

func TestMCPAggregatorAuthenticatesOnceAtTheAggregator(t *testing.T) {
	ts, orders, github := startMCPAggregatorSecurityTest(t)
	githubOnly := mcpProxyKey(t, ts, "github-mcp")

	valid := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))
	missing := postModernToolsList(t, ts, "/company-tools/", "")
	proxyOnly := postModernToolsList(t, ts, "/company-tools/", githubOnly)
	proxyOnlyCall := postMCPToolsCall(t, ts, githubOnly, toolCallParams("github__list_issues", `{}`, ""))

	require.Equal(t, http.StatusOK, valid.status, valid.body)
	assert.Equal(t, []string{"github__create_issue", "github__list_issues", "orders__create_order", "orders__list_orders"}, valid.tools)
	assert.Equal(t, http.StatusUnauthorized, missing.status, missing.body)
	assert.NotContains(t, missing.body, "orders__", "no tool leaks to an unauthenticated caller")
	assert.Equal(t, http.StatusForbidden, proxyOnly.status, "a key for an aggregated proxy grants nothing on the aggregator: %s", proxyOnly.body)
	assert.NotContains(t, proxyOnly.body, "github__")
	assert.Equal(t, http.StatusForbidden, proxyOnlyCall.status, proxyOnlyCall.body)
	assert.Empty(t, github.observed(mcp.MethodToolsCall))
	assert.Empty(t, orders.observed(mcp.MethodToolsCall))
}

func TestMCPAggregatorPolicyToolPatternsMatchAggregatedNames(t *testing.T) {
	ts, orders, github := startMCPAggregatorSecurityTest(t)
	key := companyToolsPolicyKey(t, ts, user.AccessDefinition{MCPAccessRights: user.MCPAccessRights{
		Tools: user.AccessControlRules{Allowed: []string{"orders__.*"}, Blocked: []string{"github__.*"}},
	}})

	list := postModernToolsList(t, ts, "/company-tools/", key)
	blocked := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))
	allowed := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

	require.Equal(t, http.StatusOK, list.status, list.body)
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, list.tools)

	assert.Equal(t, http.StatusForbidden, blocked.status, blocked.body)
	require.NotNil(t, blocked.rpc.Error, blocked.body)
	assert.Equal(t, jsonrpcerrors.CodeModernAccessDenied, blocked.rpc.Error.Code, "the JSON-RPC access-denied code")
	assert.Equal(t, "tool 'github__list_issues' is not available", blocked.rpc.Error.Message)
	assert.Contains(t, blocked.body, `"id":"call-1"`)
	assert.Empty(t, github.observed(mcp.MethodToolsCall), "the blocked call never reaches github")

	assert.Equal(t, http.StatusOK, allowed.status, allowed.body)
	assert.Nil(t, allowed.rpc.Error, allowed.body)
	assert.Len(t, orders.observed(mcp.MethodToolsCall), 1)
}

func TestMCPAggregatorPolicyBlocksANamespacedTool(t *testing.T) {
	ts, _, github := startMCPAggregatorSecurityTest(t)
	key := companyToolsPolicyKey(t, ts, user.AccessDefinition{MCPAccessRights: user.MCPAccessRights{
		Tools: user.AccessControlRules{Blocked: []string{"github__create_issue"}},
	}})

	list := postModernToolsList(t, ts, "/company-tools/", key)
	blocked := postMCPToolsCall(t, ts, key, toolCallParams("github__create_issue", `{}`, ""))
	allowed := postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))

	assert.Equal(t, []string{"github__list_issues", "orders__create_order", "orders__list_orders"}, list.tools)
	assert.Equal(t, http.StatusForbidden, blocked.status, blocked.body)
	require.NotNil(t, blocked.rpc.Error, blocked.body)
	assert.Equal(t, jsonrpcerrors.CodeModernAccessDenied, blocked.rpc.Error.Code)
	assert.Equal(t, http.StatusOK, allowed.status, allowed.body)
	calls := github.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1, "only the allowed call reaches github")
	assert.JSONEq(t, `"list_issues"`, string(calls[0].Params["name"]))
}

// TestMCPAggregatorPolicyBlocksOnlyTheAggregatedName checks that a rule
// written with the proxy's own tool name does not match: rules see the name
// the agent sends.
func TestMCPAggregatorPolicyBlocksOnlyTheAggregatedName(t *testing.T) {
	ts, _, github := startMCPAggregatorSecurityTest(t)
	key := companyToolsPolicyKey(t, ts, user.AccessDefinition{MCPAccessRights: user.MCPAccessRights{
		Tools: user.AccessControlRules{Blocked: []string{"create_issue"}},
	}})

	res := postMCPToolsCall(t, ts, key, toolCallParams("github__create_issue", `{}`, ""))

	assert.Equal(t, http.StatusOK, res.status, res.body)
	assert.Len(t, github.observed(mcp.MethodToolsCall), 1)
}
