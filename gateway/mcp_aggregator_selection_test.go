package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

func selecting(apiID, alias string, tools ...string) oas.TykMCPAggregatorUpstream {
	return oas.TykMCPAggregatorUpstream{APIID: apiID, Alias: alias, Tools: tools}
}

// startMCPAggregatorSelectionTest loads company-tools over orders-mcp and
// github-mcp, remote MCP proxies over the given upstreams, with the given
// aggregated proxy entries.
func startMCPAggregatorSelectionTest(t *testing.T, orders, github *mcpRoutingUpstream, upstreams ...oas.TykMCPAggregatorUpstream) (*Test, string) {
	t.Helper()
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("orders-mcp", orders.URL),
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(upstreams...),
	)
	return ts, companyToolsKey(t, ts)
}

func listedToolNames(t *testing.T, ts *Test, key string) []string {
	t.Helper()
	res := postMCPTestCall(t, ts, "/company-tools/", modernCall(mcp.MethodToolsList, key))
	require.Equal(t, http.StatusOK, res.status, res.body)
	names, _ := mcpListedTools(t, res)
	return names
}

func mcpAggregatorWarningsWith(hook interface{ AllEntries() []*logrus.Entry }, message string) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == message {
			out = append(out, entry)
		}
	}
	return out
}

func mcpAggregatorMissingToolWarnings(hook interface{ AllEntries() []*logrus.Entry }) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == mcpAggregatorSelectedToolMissingMsg {
			out = append(out, entry)
		}
	}
	return out
}

func TestMCPAggregatorSelects(t *testing.T) {
	all := mcpaggregator.Upstream{APIID: "github-mcp", Alias: "github"}
	some := mcpaggregator.Upstream{APIID: "github-mcp", Alias: "github", Tools: []string{"list_issues", "search"}}
	none := mcpaggregator.Upstream{APIID: "github-mcp", Alias: "github", Tools: []string{}}

	tests := []struct {
		name     string
		upstream mcpaggregator.Upstream
		tool     string
		selected bool
	}{
		{name: "no selection includes every tool", upstream: all, tool: "create_issue", selected: true},
		{name: "selected tool", upstream: some, tool: "list_issues", selected: true},
		{name: "other selected tool", upstream: some, tool: "search", selected: true},
		{name: "tool outside the selection", upstream: some, tool: "create_issue"},
		{name: "names match case-sensitively", upstream: some, tool: "List_Issues"},
		{name: "names match exactly", upstream: some, tool: "list_issues "},
		{name: "empty selection includes no tool", upstream: none, tool: "list_issues"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.selected, mcpAggregatorSelects(tc.upstream, tc.tool))
			assert.Equal(t, tc.selected, newMCPAggregatorToolSelection(tc.upstream).selects(tc.tool), "tools/list applies the same selection as tools/call")
		})
	}
}

func TestMCPAggregatorListsEveryToolWithoutASelection(t *testing.T) {
	ts, key := startMCPAggregatorSelectionTest(t,
		newMCPRoutingUpstream(t, namedTools("list_orders")...),
		newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue", "search")...),
		aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github"),
	)

	assert.Equal(t, []string{"github__create_issue", "github__list_issues", "github__search", "orders__list_orders"}, listedToolNames(t, ts, key))
}

func TestMCPAggregatorListsOnlySelectedTools(t *testing.T) {
	ts, key := startMCPAggregatorSelectionTest(t,
		newMCPRoutingUpstream(t, namedTools("list_orders")...),
		newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue", "search")...),
		aggregated("orders-mcp", "orders"), selecting("github-mcp", "github", "list_issues"),
	)

	names := listedToolNames(t, ts, key)

	assert.Equal(t, []string{"github__list_issues", "orders__list_orders"}, names)
	assert.NotContains(t, names, "github__create_issue")
	assert.NotContains(t, names, "github__search")
}

func TestMCPAggregatorRejectsADeselectedToolWithoutCallingTheProxy(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue", "search")...)
	github.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorSelectionTest(t,
		newMCPRoutingUpstream(t, namedTools("list_orders")...), github,
		aggregated("orders-mcp", "orders"), selecting("github-mcp", "github", "list_issues"),
	)

	res := postMCPToolsCall(t, ts, key, toolCallParams("github__create_issue", `{"title":"guessed"}`, ""))

	assert.Equal(t, http.StatusBadRequest, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcp.JSONRPCInvalidParams, res.rpc.Error.Code)
	assert.Equal(t, `unknown tool "github__create_issue"`, res.rpc.Error.Message)
	assert.Contains(t, res.body, `"id":"call-1"`)
	github.mu.Lock()
	requests := len(github.requests)
	github.mu.Unlock()
	assert.Zero(t, requests, "a deselected tool never reaches the proxy")

	res = postMCPToolsCall(t, ts, key, toolCallParams("github__list_issues", `{}`, ""))
	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Len(t, github.observed(mcp.MethodToolsCall), 1, "a selected tool is forwarded")
}

func TestMCPAggregatorAppliesEachProxysSelectionIndependently(t *testing.T) {
	ts, key := startMCPAggregatorSelectionTest(t,
		newMCPRoutingUpstream(t, namedTools("list_orders", "create_order", "search")...),
		newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue", "search")...),
		selecting("orders-mcp", "orders", "list_orders", "create_order"), selecting("github-mcp", "github", "list_issues"),
	)

	assert.Equal(t, []string{"github__list_issues", "orders__create_order", "orders__list_orders"}, listedToolNames(t, ts, key))
}

func TestMCPAggregatorSelectsByTheNameTheProxyExposes(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	githubREST := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("w.Write: %v", err)
		}
	}))
	t.Cleanup(githubREST.Close)
	source := mcpRuntimeDoc("github-rest", githubREST.URL)
	source.Paths.Set("/issues", &openapi3.PathItem{
		Get:  &openapi3.Operation{OperationID: "list_issues", Summary: "List issues", Responses: openapi3.NewResponses()},
		Post: &openapi3.Operation{OperationID: "create_issue", Summary: "Create issue", Responses: openapi3.NewResponses()},
	})
	proxyDoc := mcpRuntimeDoc("github-mcp", oas.AdapterLoopURL("github-rest"))
	proxyDoc.SetTykMCPServerExtension(&oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{{
		Source: oas.TykMCPServerSource{OperationID: "list_issues"},
		Name:   "list_open_issues",
	}}})
	load := func(tools ...string) {
		ts.Gw.LoadAPI(
			requireToken(mcpRuntimeOASSpec(source, false)),
			requireToken(mcpRuntimeOASSpec(proxyDoc, false)),
			companyToolsRuntimeSpec(selecting("github-mcp", "github", tools...)),
		)
	}

	load("list_open_issues")
	key := companyToolsKey(t, ts)
	assert.Equal(t, []string{"github__list_open_issues"}, listedToolNames(t, ts, key))

	load("list_issues", "create_issue")
	assert.Equal(t, []string{"github__create_issue"}, listedToolNames(t, ts, key), "the source name of a renamed tool selects nothing")
}

func TestMCPAggregatorOmitsASelectedToolTheProxyNoLongerExposesWithAWarning(t *testing.T) {
	ts, _, ordersBackend := startMCPAggregatorRuntimeTest(t)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	load := func(source *APISpec) {
		ts.Gw.LoadAPI(
			source,
			ordersMCPProxyRuntimeSpec(),
			remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
			companyToolsRuntimeSpec(selecting("orders-mcp", "orders", "list_orders", "create_order"), aggregated("github-mcp", "github")),
		)
	}
	load(ordersRESTSourceSpec(ordersBackend.URL, false))
	key := companyToolsKey(t, ts)
	require.Equal(t, []string{"github__list_issues", "orders__create_order", "orders__list_orders"}, listedToolNames(t, ts, key))

	withoutListOrders := ordersRESTSourceSpec(ordersBackend.URL, false)
	withoutListOrders.OAS.Paths.Find("/orders").Get = nil
	load(withoutListOrders)
	hook := log.GetTestHook(t)

	assert.Equal(t, []string{"github__list_issues", "orders__create_order"}, listedToolNames(t, ts, key), "the other tools keep being served")
	warnings := mcpAggregatorMissingToolWarnings(hook)
	require.Len(t, warnings, 1)
	assert.Equal(t, "list_orders", warnings[0].Data["tool"])
	assert.Equal(t, "orders", warnings[0].Data["alias"])
	assert.Equal(t, "orders-mcp", warnings[0].Data["upstream_api_id"])
	assert.Equal(t, "company-tools", warnings[0].Data["aggregator_api_id"])
}

func TestMCPAggregatorFindsSelectedToolsOnLaterPages(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	github.pager = func(cursor string) ([]string, string) {
		if cursor == "" {
			return []string{"search_repos"}, "page-2"
		}
		return []string{"create_issue"}, ""
	}
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(selecting("github-mcp", "github", "create_issue")))
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__create_issue"}, res.tools)
	assert.Empty(t, mcpAggregatorMissingToolWarnings(hook), "a tool on a later page is not missing")
}

func TestMCPAggregatorOmitsAndRefusesToolsGainedLaterWithNamesOverTheLimit(t *testing.T) {
	long := "export_order_volumes_" + strings.Repeat("x", 125-len("export_order_volumes_"))
	fits := "export_issue_volumes_" + strings.Repeat("x", 120-len("export_issue_volumes_"))
	orders := newMCPRoutingUpstream(t, namedTools("list_orders")...)
	orders.call = answering(`{"content":[]}`)
	github := newMCPRoutingUpstream(t, namedTools("list_issues")...)
	github.call = answering(`{"content":[]}`)
	ts, key := startMCPAggregatorSelectionTest(t, orders, github, aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github"))
	require.Equal(t, []string{"github__list_issues", "orders__list_orders"}, listedToolNames(t, ts, key))

	orders.mu.Lock()
	orders.descriptors = append(orders.descriptors, namedTools(long)...)
	orders.mu.Unlock()
	github.mu.Lock()
	github.descriptors = append(github.descriptors, namedTools(fits)...)
	github.mu.Unlock()
	hook := log.GetTestHook(t)

	assert.Equal(t, []string{"github__" + fits, "github__list_issues", "orders__list_orders"}, listedToolNames(t, ts, key), "a 128-character name is kept")
	warnings := mcpAggregatorWarningsWith(hook, mcpAggregatorToolNameTooLongMsg)
	require.Len(t, warnings, 1)
	assert.Equal(t, long, warnings[0].Data["tool"])
	assert.Equal(t, "orders", warnings[0].Data["alias"])
	assert.Equal(t, "orders-mcp", warnings[0].Data["upstream_api_id"])
	assert.Equal(t, `"orders__" plus the tool name is 133 characters, over the 128 character limit for MCP tool names`, warnings[0].Data["reason"])

	res := postMCPToolsCall(t, ts, key, toolCallParams("orders__"+long, `{}`, ""))
	assert.Equal(t, http.StatusBadRequest, res.status, res.body)
	require.NotNil(t, res.rpc.Error, res.body)
	assert.Equal(t, mcp.JSONRPCInvalidParams, res.rpc.Error.Code)
	assert.Equal(t, `unknown tool "orders__`+long+`"`, res.rpc.Error.Message)
	assert.Empty(t, orders.observed(mcp.MethodToolsCall), "an over-long name never reaches the proxy")

	res = postMCPToolsCall(t, ts, key, toolCallParams("github__"+fits, `{}`, ""))
	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Len(t, github.observed(mcp.MethodToolsCall), 1)
}
