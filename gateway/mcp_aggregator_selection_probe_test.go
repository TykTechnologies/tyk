package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func TestMCPAggregatorProbeReadsTheProxysOwnToolView(t *testing.T) {
	ts := startMCPAggregatorAdmissionTest(t, newLatestOnlyMCPUpstream(t, "list_issues").URL)
	aggregator := mcpAggregatorSpec("company-tools", mcpAggregatorRuntimeOrg, aggregated("orders-narrow", "orders"))
	parent := (&http.Request{Header: http.Header{}, Host: mcpAggregatorProbeHost, RemoteAddr: mcpAggregatorProbeRemoteAddr}).WithContext(context.Background())
	d := mcpAggregatorDispatcher{gw: ts.Gw, aggregator: aggregator}

	narrow := d.probeUpstream(parent, ts.Gw.getApiSpec("orders-narrow"), "orders")
	full := d.probeUpstream(parent, ts.Gw.getApiSpec("orders-mcp"), "orders")

	require.NoError(t, narrow.ToolsErr)
	assert.NoError(t, narrow.Version)
	assert.Equal(t, []string{"list_orders"}, narrow.Tools, "create_order, excluded by the proxy's own view, is never offered")
	require.NoError(t, full.ToolsErr)
	assert.ElementsMatch(t, []string{"list_orders", "create_order"}, full.Tools, "the same source through a proxy without restrictions")
}

func TestMCPAggregatorWarnsWhenItCannotCheckAProxysTools(t *testing.T) {
	down := newLatestOnlyMCPUpstream(t, "list_issues")
	down.Close()
	ts := startMCPAggregatorCompatTest(t, down.URL)
	hook := log.GetTestHook(t)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, "POST", mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("orders-mcp", "orders", "list_orders"),
		selecting("github-mcp", "github", "delete_repo"),
	))

	require.Equal(t, http.StatusOK, res.code, res.body)
	warnings := mcpAggregatorToolCheckWarnings(hook, mcpAggregatorToolsUncheckedMsg, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, "github", warnings[0].Data["alias"])
	assert.Regexp(t, `^tools/list: `, warnings[0].Data["reason"])
	assert.Len(t, mcpAggregatorToolCheckWarnings(hook, mcpAggregatorVersionUncheckedMsg, "github-mcp"), 1, "the version check warning is kept")
	assert.Empty(t, mcpAggregatorToolCheckWarnings(hook, mcpAggregatorToolsUncheckedMsg, "orders-mcp"))
}

func TestMCPAggregatorSelectionError(t *testing.T) {
	long := longToolName
	for name, tc := range map[string]struct {
		ref     oas.TykMCPAggregatorUpstream
		exposed []string
		want    string
	}{
		"no selection":            {aggregated("github-mcp", "github"), []string{"list_issues", "search"}, ""},
		"exposed selection":       {selecting("github-mcp", "github", "search"), []string{"list_issues", "search"}, ""},
		"missing tool":            {selecting("github-mcp", "github", "search", "delete_repo"), []string{"list_issues", "search"}, `tool "delete_repo" not found in aggregated MCP proxy "github"`},
		"first missing reported":  {selecting("github-mcp", "github", "a", "b"), nil, `tool "a" not found in aggregated MCP proxy "github"`},
		"case differs":            {selecting("github-mcp", "github", "Search"), []string{"search"}, `tool "Search" not found in aggregated MCP proxy "github"`},
		"long exposed tool":       {aggregated("orders-long", "orders"), []string{"list_orders", long}, `tool "` + long + `" of aggregated MCP proxy "orders" cannot be aggregated: "orders__" plus the tool name is 133 characters, over the 128 character limit for MCP tool names`},
		"long tool deselected":    {selecting("orders-long", "orders", "list_orders"), []string{"list_orders", long}, ""},
		"exactly 128":             {aggregated("orders-long", "o"), []string{long}, ""},
		"limit counts characters": {aggregated("orders-long", "o"), []string{long[:124] + "é"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, mcpAggregatorSelectionError(tc.ref, tc.exposed))
		})
	}
}
