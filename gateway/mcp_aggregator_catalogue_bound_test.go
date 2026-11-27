package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func generatedToolNames(n int) []string {
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		names = append(names, fmt.Sprintf("tool_%05d", i))
	}
	return names
}

// pageToolNames serves names as tools/list pages of the given size.
func pageToolNames(names []string, size int) func(cursor string) ([]string, string) {
	return func(cursor string) ([]string, string) {
		start := 0
		if cursor != "" {
			if _, err := fmt.Sscanf(cursor, "page-%d", &start); err != nil {
				panic(fmt.Sprintf("unexpected tools/list cursor %q: %v", cursor, err))
			}
		}
		end := min(start+size, len(names))
		if end == len(names) {
			return names[start:end], ""
		}
		return names[start:end], fmt.Sprintf("page-%d", end)
	}
}

func TestMCPAggregatorCatalogueToolLimit(t *testing.T) {
	// orders-mcp contributes 2 tools and is listed first, so github-mcp is the
	// aggregated proxy that reaches the limit.
	tests := []struct {
		name        string
		githubTools int
		served      int
	}{
		{name: "catalogue at the limit is served", githubTools: mcpAggregatorMaxCatalogueTools - 2, served: mcpAggregatorMaxCatalogueTools},
		{name: "proxy that would exceed the limit is omitted", githubTools: mcpAggregatorMaxCatalogueTools - 1, served: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
			github.pager = pageToolNames(generatedToolNames(tc.githubTools), 2500)
			ts.Gw.LoadAPI(
				ordersRESTSourceSpec(ordersBackend.URL, false),
				ordersMCPProxyRuntimeSpec(),
				githubMCPProxyRuntimeSpec(github.URL),
				companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
			)
			hook := log.GetTestHook(t)

			res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

			require.Equal(t, http.StatusOK, res.status)
			assert.Len(t, res.tools, tc.served)
			assert.Contains(t, res.tools, "orders__list_orders", "the proxies within the limit keep being served")
			warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
			if tc.served == mcpAggregatorMaxCatalogueTools {
				assert.Empty(t, warnings)
				return
			}
			require.Len(t, warnings, 1)
			assert.Equal(t, "github", warnings[0].Data["alias"])
			assert.Equal(t, "catalogue limit: the aggregator serves at most 10000 tools", warnings[0].Data["reason"])
			assert.Empty(t, mcpAggregatorOmissionWarnings(hook, "orders-mcp"))
		})
	}
}

func TestMCPAggregatorOmitsAggregatedProxyListingMoreToolsThanTheCatalogueHolds(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	var pages atomic.Int32
	names := generatedToolNames(mcpAggregatorMaxCatalogueTools + 5000)
	pager := pageToolNames(names, 2500)
	github.pager = func(cursor string) ([]string, string) {
		pages.Add(1)
		return pager(cursor)
	}
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")),
	)
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, res.tools)
	assert.EqualValues(t, 5, pages.Load(), "pages past the limit are not read")
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "tools/list failed: returned more than 10000 tools", warnings[0].Data["reason"])
}

func TestMCPAggregatorCatalogueOverflow(t *testing.T) {
	assert.Empty(t, mcpAggregatorCatalogueOverflow(mcpAggregatorMaxCatalogueTools, mcpAggregatorMaxCatalogueBytes))
	assert.Equal(t, "catalogue limit: the aggregator serves at most 10000 tools", mcpAggregatorCatalogueOverflow(mcpAggregatorMaxCatalogueTools+1, 0))
	assert.Equal(t, "catalogue limit: the aggregator serves at most 33554432 bytes of tool definitions", mcpAggregatorCatalogueOverflow(1, mcpAggregatorMaxCatalogueBytes+1))
}

func TestMCPAggregatorToolsSize(t *testing.T) {
	tools := []mcpAggregatorTool{
		{Definition: map[string]json.RawMessage{"name": json.RawMessage(`"a__b"`)}},
		{Definition: map[string]json.RawMessage{"name": json.RawMessage(`"a__c"`), "description": json.RawMessage(`"xyz"`)}},
	}
	assert.Equal(t, (4+6)+(4+6)+(11+5), mcpAggregatorToolsSize(tools))
	assert.Zero(t, mcpAggregatorToolsSize(nil))
}

func TestMCPAggregatorCatalogueToolLimitCountsOnlySelectedTools(t *testing.T) {
	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	github.pager = pageToolNames(generatedToolNames(mcpAggregatorMaxCatalogueTools-1), 2500)
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(github.URL),
		companyToolsRuntimeSpec(aggregated("orders-mcp", "orders"), selecting("github-mcp", "github", "tool_00042")),
	)
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, []string{"github__tool_00042", "orders__create_order", "orders__list_orders"}, res.tools)
	assert.Empty(t, mcpAggregatorOmissionWarnings(hook, "github-mcp"), "unselected tools do not count towards the catalogue limit")
}

// loadGithubWithGhosts loads company-tools with orders-mcp, github-mcp and
// enough aggregated proxies that are not loaded to configure the given total.
func loadGithubWithGhosts(ts *Test, configured int, githubURL, ordersURL string) {
	upstreams := []oas.TykMCPAggregatorUpstream{aggregated("orders-mcp", "orders"), aggregated("github-mcp", "github")}
	for i := len(upstreams); i < configured; i++ {
		upstreams = append(upstreams, aggregated(fmt.Sprintf("ghost-%d", i), fmt.Sprintf("ghost%d", i)))
	}
	ts.Gw.LoadAPI(
		ordersRESTSourceSpec(ordersURL, false),
		ordersMCPProxyRuntimeSpec(),
		githubMCPProxyRuntimeSpec(githubURL),
		companyToolsRuntimeSpec(upstreams...),
	)
}

// TestMCPAggregatorServesALargeListingHoweverManyProxiesAreAggregated has
// github-mcp list about 2 MiB of tools in two pages.
func TestMCPAggregatorServesALargeListingHoweverManyProxiesAreAggregated(t *testing.T) {
	for _, configured := range []int{2, 20} {
		t.Run(fmt.Sprintf("%d aggregated proxies", configured), func(t *testing.T) {
			ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
			github.descriptionPadding = 1 << 20
			github.pager = pageToolNames([]string{"search_repos", "create_issue"}, 1)
			loadGithubWithGhosts(ts, configured, github.URL, ordersBackend.URL)
			hook := log.GetTestHook(t)

			res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

			require.Equal(t, http.StatusOK, res.status)
			assert.Equal(t, []string{"github__create_issue", "github__search_repos", "orders__create_order", "orders__list_orders"}, res.tools)
			assert.Empty(t, mcpAggregatorOmissionWarnings(hook, "github-mcp"))
		})
	}
}

// TestMCPAggregatorOmitsAProxyListingMoreThanItsBudget has github-mcp list two
// pages of over half the listing budget each, each under the gateway's 10 MiB
// response limit.
func TestMCPAggregatorOmitsAProxyListingMoreThanItsBudget(t *testing.T) {
	page := mcpAggregatorMaxUpstreamListBytes * 9 / 16
	require.Less(t, page, mcpAggregatorMaxUpstreamResponseBytes, "each page fits the response limit, so only the listing budget can omit the proxy")

	ts, github, ordersBackend := startMCPAggregatorRuntimeTest(t)
	github.descriptionPadding = page
	var pages atomic.Int32
	pager := pageToolNames([]string{"search_repos", "create_issue"}, 1)
	github.pager = func(cursor string) ([]string, string) {
		pages.Add(1)
		return pager(cursor)
	}
	loadGithubWithGhosts(ts, 2, github.URL, ordersBackend.URL)
	hook := log.GetTestHook(t)

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status)
	assert.EqualValues(t, 2, pages.Load())
	assert.Equal(t, []string{"orders__create_order", "orders__list_orders"}, res.tools, "the other proxies keep being served")
	warnings := mcpAggregatorOmissionWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, fmt.Sprintf("tools/list failed: responses exceed the %d byte listing budget of one aggregated proxy", mcpAggregatorMaxUpstreamListBytes), warnings[0].Data["reason"])
}

func TestMCPAggregatorResponseRecorderStaysWithinTheBudget(t *testing.T) {
	d := mcpAggregatorDispatcher{gw: &Gateway{}, budget: &mcpAggregatorByteBudget{limit: 10}}
	d.gw.SetConfig(config.Config{})

	first := d.newResponseRecorder()
	assert.Equal(t, 10, first.limit)
	_, err := first.Write([]byte("123456"))
	require.NoError(t, err)
	require.NoError(t, d.recorded(first))

	second := d.newResponseRecorder()
	assert.Equal(t, 4, second.limit, "a response is limited to what is left of the budget")
	_, err = second.Write([]byte("12345"))
	require.NoError(t, err, "a write past the budget is dropped, not failed")
	assert.Equal(t, 0, second.body.Len(), "nothing past the budget is buffered")
	assert.EqualError(t, d.recorded(second), "responses exceed the 10 byte listing budget of one aggregated proxy")

	unbudgeted := mcpAggregatorDispatcher{gw: d.gw}
	assert.Equal(t, mcpAggregatorMaxUpstreamResponseBytes, unbudgeted.newResponseRecorder().limit)
}
