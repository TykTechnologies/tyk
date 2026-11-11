package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// longToolName is 125 characters: valid on a proxy, 133 as orders__<name>.
var longToolName = "export_order_volumes_" + strings.Repeat("x", 125-len("export_order_volumes_"))

// narrowOrdersMCPProxySpec is an API-to-MCP proxy over orders-rest whose own
// tool view (x-tyk-mcp-server in allow mode) exposes list_orders only.
func narrowOrdersMCPProxySpec() *APISpec {
	doc := mcpRuntimeDoc("orders-narrow", oas.AdapterLoopURL("orders-rest"))
	allow := true
	doc.SetTykMCPServerExtension(&oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{{
		Source: oas.TykMCPServerSource{OperationID: "list_orders"},
		Allow:  &allow,
	}}})
	return requireToken(mcpRuntimeOASSpec(doc, false))
}

// startMCPAggregatorAdmissionTest loads what startMCPAggregatorCompatTest
// loads, orders-narrow and any extra specs, without any aggregator unless
// one is among the extras.
func startMCPAggregatorAdmissionTest(t *testing.T, githubURL string, extra ...*APISpec) *Test {
	t.Helper()
	ts, _, ordersBackend := startMCPAggregatorRuntimeTest(t)
	ts.Gw.LoadAPI(append([]*APISpec{
		ordersRESTSourceSpec(ordersBackend.URL, false),
		ordersMCPProxyRuntimeSpec(),
		narrowOrdersMCPProxySpec(),
		githubMCPProxyRuntimeSpec(githubURL),
	}, extra...)...)
	return ts
}

func mcpAggregatorToolCheckWarnings(hook interface{ AllEntries() []*logrus.Entry }, message, upstreamAPIID string) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == message && entry.Data["upstream_api_id"] == upstreamAPIID {
			out = append(out, entry)
		}
	}
	return out
}

func TestMCPAggregatorRejectsSelectingAToolTheProxyDoesNotExpose(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues", "create_issue", "search")
	ts := startMCPAggregatorAdmissionTest(t, github.URL, companyToolsRuntimeSpec(aggregated("github-mcp", "github")))

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, method, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
				aggregated("orders-mcp", "orders"),
				selecting("github-mcp", "github", "list_issues", "delete_repo"),
			))

			assert.Equal(t, http.StatusBadRequest, res.code, res.body)
			assert.False(t, res.nextCalled)
			assert.Contains(t, res.body, `tool \"delete_repo\" not found in aggregated MCP proxy \"github\"`)
		})
	}
}

func TestHandleAddApiOASRejectsSelectingAToolTheProxyDoesNotExpose(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, newLatestOnlyMCPUpstream(t, "list_issues").URL)

	body, err := json.Marshal(mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, selecting("github-mcp", "github", "delete_repo")))
	require.NoError(t, err)
	resp, code := ts.Gw.handleAddApi(httptest.NewRequest(http.MethodPost, "/tyk/apis/oas", bytes.NewReader(body)), afero.NewMemMapFs(), true)

	require.Equal(t, http.StatusBadRequest, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Equal(t, `tool "delete_repo" not found in aggregated MCP proxy "github"`, msg.Message)
}

func TestMCPAggregatorAdmitsASelectionOfExposedTools(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues", "create_issue", "search")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	hook := log.GetTestHook(t)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("orders-mcp", "orders", "list_orders", "create_order"),
		selecting("github-mcp", "github", "list_issues"),
	))

	require.Equal(t, http.StatusOK, res.code, res.body)
	assert.True(t, res.nextCalled)
	for _, entry := range hook.AllEntries() {
		assert.NotEqual(t, logrus.WarnLevel, entry.Level, entry.Message)
	}
}

func TestMCPAggregatorSelectionMatchesExposedNamesCaseSensitively(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, newLatestOnlyMCPUpstream(t, "list_issues").URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("github-mcp", "github", "List_Issues"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `tool \"List_Issues\" not found in aggregated MCP proxy \"github\"`)
}

func TestMCPAggregatorAdmissionReadsEachProxyOnce(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues", "create_issue")
	ts := startMCPAggregatorCompatTest(t, github.URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("github-mcp", "github", "list_issues"),
	))

	require.Equal(t, http.StatusOK, res.code, res.body)
	var methods []string
	for _, req := range github.observed() {
		methods = append(methods, req.Method)
	}
	assert.Equal(t, []string{mcp.MethodServerDiscover, mcp.MethodToolsList}, methods, "one probe checks the version and reads the tools")
}

func TestMCPAggregatorAdmissionFindsSelectedToolsOnLaterPages(t *testing.T) {
	github := newMockRemoteMCPServer(t)
	github.pager = func(cursor string) ([]string, string) {
		if cursor == "" {
			return []string{"search_repos"}, "page-2"
		}
		return []string{"create_issue"}, ""
	}
	ts := startMCPAggregatorCompatTest(t, github.URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("github-mcp", "github", "create_issue"),
	))
	require.Equal(t, http.StatusOK, res.code, res.body)

	res = postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("github-mcp", "github", "delete_repo"),
	))
	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `tool \"delete_repo\" not found in aggregated MCP proxy \"github\"`, "a proxy without server/discover still has its selection checked")
}

func TestMCPAggregatorRejectsSelectingAToolExcludedByTheProxysOwnView(t *testing.T) {
	ts := startMCPAggregatorAdmissionTest(t, newLatestOnlyMCPUpstream(t, "list_issues").URL)

	for name, tools := range map[string][]string{
		"with an exposed tool": {"list_orders", "create_order"},
		"alone":                {"create_order"},
	} {
		t.Run(name, func(t *testing.T) {
			res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
				selecting("orders-narrow", "orders", tools...),
				aggregated("github-mcp", "github"),
			))

			assert.Equal(t, http.StatusBadRequest, res.code, res.body)
			assert.Contains(t, res.body, `tool \"create_order\" not found in aggregated MCP proxy \"orders\"`)
		})
	}

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("orders-narrow", "orders", "list_orders"),
	))
	assert.Equal(t, http.StatusOK, res.code, res.body)
}

func TestMCPAggregatorRejectsAggregatedToolNamesOverTheLimit(t *testing.T) {
	require.Len(t, longToolName, 125)
	ts := startMCPAggregatorCompatTest(t, newLatestOnlyMCPUpstream(t, "list_orders", longToolName).URL)
	admit := func(upstream oas.TykMCPAggregatorUpstream) mcpAggregatorAdmissionResult {
		return postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, upstream))
	}

	for name, upstream := range map[string]oas.TykMCPAggregatorUpstream{
		"no selection":       aggregated("github-mcp", "orders"),
		"long tool selected": selecting("github-mcp", "orders", "list_orders", longToolName),
	} {
		t.Run(name, func(t *testing.T) {
			res := admit(upstream)

			assert.Equal(t, http.StatusBadRequest, res.code, res.body)
			assert.Contains(t, res.body, `tool \"`+longToolName+`\" of aggregated MCP proxy \"orders\" cannot be aggregated: \"orders__\" plus the tool name is 133 characters, over the 128 character limit for MCP tool names`)
		})
	}

	t.Run("long tool deselected", func(t *testing.T) {
		res := admit(selecting("github-mcp", "orders", "list_orders"))
		assert.Equal(t, http.StatusOK, res.code, res.body)
	})
	t.Run("exactly 128 characters", func(t *testing.T) {
		res := admit(aggregated("github-mcp", "o"))
		assert.Equal(t, http.StatusOK, res.code, res.body)
	})
	t.Run("129 characters", func(t *testing.T) {
		res := admit(aggregated("github-mcp", "or"))
		assert.Equal(t, http.StatusBadRequest, res.code, res.body)
		assert.Contains(t, res.body, `\"or__\" plus the tool name is 129 characters`)
	})
}

func TestMCPAggregatorAdmitsAnUnavailableProxyWithoutCheckingItsSelection(t *testing.T) {
	down := newLatestOnlyMCPUpstream(t, "list_issues")
	down.Close()
	ts := startMCPAggregatorCompatTest(t, down.URL)

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg,
		selecting("orders-mcp", "orders", "list_orders"),
		selecting("github-mcp", "github", "delete_repo"),
	))

	require.Equal(t, http.StatusOK, res.code, res.body)
	assert.True(t, res.nextCalled)
}

func TestMCPAggregatorRuntimeAppliesTheSelectionOfAProxyAdmittedWhileDown(t *testing.T) {
	github := newMCPRoutingUpstream(t, namedTools("list_issues", "create_issue")...)
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	ts.Gw.LoadAPI(
		remoteMCPProxyRuntimeSpec("github-mcp", github.URL),
		companyToolsRuntimeSpec(selecting("github-mcp", "github", "list_issues", "delete_repo")),
	)
	hook := log.GetTestHook(t)

	assert.Equal(t, []string{"github__list_issues"}, listedToolNames(t, ts, companyToolsKey(t, ts)))
	warnings := mcpAggregatorMissingToolWarnings(hook)
	require.Len(t, warnings, 1)
	assert.Equal(t, "delete_repo", warnings[0].Data["tool"])
}
