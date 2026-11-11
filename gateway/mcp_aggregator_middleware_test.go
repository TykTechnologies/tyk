package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// companyToolsWithRequestHeaders is company-tools over orders-mcp and
// github-mcp with an API-level request header transform adding headers.
func companyToolsWithRequestHeaders(add ...oas.Header) *APISpec {
	doc := mcpRuntimeDoc("company-tools", oas.MCPAggregatorTargetURL)
	doc.SetTykMCPAggregatorExtension(&oas.TykMCPAggregator{Upstreams: []oas.TykMCPAggregatorUpstream{
		aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github"),
	}})
	ext := doc.GetTykExtension()
	ext.Middleware = &oas.Middleware{Global: &oas.Global{
		TransformRequestHeaders: &oas.TransformHeaders{Enabled: true, Add: add},
	}}
	return requireToken(mcpRuntimeOASSpec(doc, true))
}

func startMCPAggregatorWithRequestHeaders(t *testing.T, add ...oas.Header) (*Test, string, *mcpRoutingUpstream, *mcpRoutingUpstream) {
	t.Helper()
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	github.call = answering(`{"content":[]}`)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsWithRequestHeaders(add...),
	)
	return ts, companyToolsKey(t, ts), orders, github
}

func TestMCPAggregatorRequestHeaderTransformAppliesBeforeRouting(t *testing.T) {
	ts, key, orders, github := startMCPAggregatorWithRequestHeaders(t, oas.Header{Name: "X-Acme-Tenant", Value: "acme"})

	for _, tool := range []string{"orders__list_orders", "github__list_issues"} {
		res := postMCPToolsCall(t, ts, key, toolCallParams(tool, `{}`, ""), "X-Acme-Tenant", "spoofed", "X-Agent-Note", "consumer header")
		require.Equal(t, http.StatusOK, res.status, res.body)
	}

	for name, upstream := range map[string]*mcpRoutingUpstream{"orders": orders, "github": github} {
		calls := upstream.observed(mcp.MethodToolsCall)
		require.Len(t, calls, 1, name)
		assert.Equal(t, []string{"acme"}, calls[0].Header.Values("X-Acme-Tenant"), "%s receives the transform's value, not the agent's", name)
		assert.Empty(t, calls[0].Header.Get("X-Agent-Note"), "%s: other agent headers stay at the aggregator", name)
		assert.Empty(t, calls[0].Header.Get("Authorization"), "%s: the agent's key is not forwarded", name)
	}
}

func TestMCPAggregatorRequestHeaderTransformDoesNotForwardCredentialsOrProtocolHeaders(t *testing.T) {
	ts, key, orders, _ := startMCPAggregatorWithRequestHeaders(t,
		oas.Header{Name: "X-Acme-Tenant", Value: "acme"},
		oas.Header{Name: "Authorization", Value: "Bearer operator"},
		oas.Header{Name: "Proxy-Authorization", Value: "Basic operator"},
		oas.Header{Name: "Cookie", Value: "session=operator"},
		oas.Header{Name: "Proxy-Foo", Value: "p"},
		oas.Header{Name: "X-Forwarded-For", Value: "10.9.9.9"},
		oas.Header{Name: "X-Forwarded-Host", Value: "evil.example"},
		oas.Header{Name: "X-Real-IP", Value: "10.8.8.8"},
		oas.Header{Name: "Forwarded", Value: "for=10.7.7.7"},
		oas.Header{Name: "X-Tyk-Internal", Value: "true"},
		oas.Header{Name: "Mcp-Method", Value: "tools/list"},
		oas.Header{Name: "Mcp-Name", Value: "delete_all"},
		oas.Header{Name: "Content-Type", Value: "text/plain"},
	)

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""))

	require.Equal(t, http.StatusOK, res.status, res.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	header := calls[0].Header
	assert.Equal(t, "acme", header.Get("X-Acme-Tenant"))
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Proxy-Foo", "X-Real-IP", "Forwarded", "X-Tyk-Internal", "X-Forwarded-Host"} {
		assert.Empty(t, header.Get(name), name)
	}
	assert.NotContains(t, strings.Join(header.Values("X-Forwarded-For"), ","), "10.9.9.9", "the client address is not taken from the transform")
	assert.Equal(t, mcp.MethodToolsCall, header.Get(mcp.HeaderMethod))
	assert.Equal(t, "list_orders", header.Get(mcp.HeaderName))
	assert.Equal(t, contentTypeJSON, header.Get(headerContentType))
}

func TestMCPAggregatorForwardsNoHeadersWithoutATransform(t *testing.T) {
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorRoutingTest(t, orders, newMCPRoutingUpstream(t, namedTools("list_issues")...))

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__list_orders", `{}`, ""), "X-Acme-Tenant", "spoofed")

	require.Equal(t, http.StatusOK, res.status, res.body)
	calls := orders.observed(mcp.MethodToolsCall)
	require.Len(t, calls, 1)
	assert.Empty(t, calls[0].Header.Get("X-Acme-Tenant"))
}

// TestMCPAggregatorForwardsTransformHeadersAlongsideTheClientIP checks that
// the transform's headers and the caller's client IP both reach an aggregated
// proxy: the proxy's IP allow list sees the agent's address while its
// upstream receives the transform's header.
func TestMCPAggregatorForwardsTransformHeadersAlongsideTheClientIP(t *testing.T) {
	const clientIP, otherIP = "203.0.113.7", "198.51.100.9"
	for name, forwarded := range map[string]string{"allowed client": clientIP, "refused client": otherIP} {
		t.Run(name, func(t *testing.T) {
			github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
			github.call = answering(`{"content":[]}`)
			doc := mcpRuntimeDoc("company-tools", oas.MCPAggregatorTargetURL)
			doc.SetTykMCPAggregatorExtension(&oas.TykMCPAggregator{Upstreams: []oas.TykMCPAggregatorUpstream{aggregated("github-mcp", "github")}})
			doc.GetTykExtension().Middleware = &oas.Middleware{Global: &oas.Global{TransformRequestHeaders: &oas.TransformHeaders{
				Enabled: true, Add: oas.Headers{{Name: "X-Acme-Tenant", Value: "acme"}},
			}}}
			ts := StartTest(nil)
			t.Cleanup(ts.Close)
			ts.Gw.LoadAPI(githubMCPProxyWithIPAccessControl(github.URL, []string{clientIP}, nil), requireToken(mcpRuntimeOASSpec(doc, true)))

			res := postMCPToolsCall(t, ts, companyToolsKey(t, ts), toolCallParams("github__list_issues", `{}`, ""), "X-Forwarded-For", forwarded)

			calls := github.observed(mcp.MethodToolsCall)
			if forwarded == otherIP {
				assert.Empty(t, calls, "the proxy's allow list sees the agent's address: %s", res.body)
				return
			}
			require.Len(t, calls, 1, res.body)
			assert.Equal(t, "acme", calls[0].Header.Get("X-Acme-Tenant"))
		})
	}
}
