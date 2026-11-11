package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

// assertMCPAggregatorCalledOnLatest checks that every request an upstream saw
// for method came from the aggregator on 2026-07-28: the Mcp-Protocol-Version
// header, the mirrored Mcp-Method header and the _meta declaration.
func assertMCPAggregatorCalledOnLatest(t *testing.T, upstream *mcpVersionedUpstream, method string) {
	t.Helper()
	var calls int
	for _, req := range upstream.observed() {
		if req.Method != method {
			continue
		}
		calls++
		assert.Equal(t, mcp.ModernProtocolVersion, req.HeaderVersion, "Mcp-Protocol-Version of %s", method)
		assert.Equal(t, method, req.HeaderMethod, "Mcp-Method of %s", method)
		assert.Equal(t, mcp.ModernProtocolVersion, req.MetaVersion, "_meta protocol version of %s", method)
	}
	require.NotZero(t, calls, "the upstream received no %s", method)
}

func TestMCPAggregatorCallsAggregatedProxiesOnTheLatestVersion(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, key := startMCPAggregatorProtocolTest(t, github)

	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Contains(t, res.body, `"github__list_issues"`)
	assertMCPAggregatorCalledOnLatest(t, github, mcp.MethodToolsList)
}

func TestMCPAggregatorOmitsAggregatedProxyThatLostTheLatestVersion(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, key := startMCPAggregatorProtocolTest(t, github)
	before := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))
	require.Contains(t, before.body, `"github__list_issues"`)

	github.setVersions(mcp.LegacyFallbackProtocolVersion)
	hook := log.GetTestHook(t)
	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.NotContains(t, res.body, "github__")
	assert.Contains(t, res.body, `"orders__list_orders"`)
	assert.Contains(t, res.body, `"orders__create_order"`)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "company-tools", warnings[0].Data["aggregator_api_id"])
	assert.Equal(t, "github", warnings[0].Data["alias"])
	assert.Equal(t, mcp.ModernProtocolVersion, warnings[0].Data["mcp_protocol_version"])
	reason, _ := warnings[0].Data["reason"].(string)
	assert.Regexp(t, `^version mismatch: does not support MCP version 2026-07-28: `, reason)
	assert.Contains(t, reason, "Unsupported protocol version")
	assert.Empty(t, mcpAggregatorOmissionWarnings(hook, "orders-mcp"))
}

func TestMCPAggregatorDowngradeLeavesDirectCallsToTheProxyAlone(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, _ := startMCPAggregatorProtocolTest(t, github)
	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = mcpAggregatorRuntimeOrg
		s.AccessRights = map[string]user.AccessDefinition{"github-mcp": {APIID: "github-mcp", APIName: "github-mcp"}}
	})

	res := postMCPTestCall(t, ts, "/github-mcp/", mcpTestCall{method: mcp.MethodToolsList, version: "2025-11-25", metaVersion: "2025-11-25", key: key})

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Contains(t, res.body, `"list_issues"`)
	observed := github.observed()
	assert.Equal(t, "2025-11-25", observed[len(observed)-1].HeaderVersion)
	assert.Equal(t, "2025-11-25", observed[len(observed)-1].MetaVersion)
}

func TestMCPAggregatorOmitsAggregatedProxyRedeployedOnASessionFirstLegacyServer(t *testing.T) {
	github := newDualMCPUpstream(t, "list_issues")
	ts, key := startMCPAggregatorProtocolTest(t, github)
	before := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))
	require.Contains(t, before.body, `"github__list_issues"`)

	// Redeploy github on a session-first legacy server; LoadAPI replaces the
	// whole set, so the other APIs are loaded again unchanged.
	ordersRest := ts.Gw.getApiSpec("orders-rest")
	require.NotNil(t, ordersRest)
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersRest.Proxy.TargetURL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(sessionFirstLegacyMCPUpstream(t).URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	hook := log.GetTestHook(t)
	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.NotContains(t, res.body, "github__")
	assert.Contains(t, res.body, `"orders__list_orders"`)
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "github", warnings[0].Data["alias"])
	reason, _ := warnings[0].Data["reason"].(string)
	assert.Regexp(t, `^version mismatch: does not support MCP version 2026-07-28: upstream requires a legacy session: `, reason)
}
