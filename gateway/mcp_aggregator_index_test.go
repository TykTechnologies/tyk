package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

func mcpAggregatorWarnings(hook interface{ AllEntries() []*logrus.Entry }) []*logrus.Entry {
	var out []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == mcpAggregatorUpstreamOmittedMsg {
			out = append(out, entry)
		}
	}
	return out
}

func TestComputeMCPAggregationAdmitsLoadedAggregatedProxies(t *testing.T) {
	ordersMCP := pairedMCPProxySpec("orders-mcp", "acme", "orders-rest", nil)
	githubMCP := mcpManagedTestSpec("github-mcp")
	githubMCP.OrgID = "acme"
	companyTools := mcpAggregatorSpec("company-tools", "acme",
		oas.TykMCPAggregatorUpstream{APIID: "orders-mcp", Alias: "orders", Tools: []string{"list_orders"}},
		aggregated("github-mcp", "github"),
	)

	snapshot := computeMCPAggregation([]*APISpec{restSourceSpec("orders-rest", "acme", true), ordersMCP, githubMCP, companyTools})

	agg, ok := snapshot.Lookup("company-tools")
	require.True(t, ok)
	assert.Equal(t, "acme", agg.OrgID)
	assert.Equal(t, []mcpaggregator.Upstream{
		{APIID: "orders-mcp", Alias: "orders", Tools: []string{"list_orders"}},
		{APIID: "github-mcp", Alias: "github"},
	}, agg.Upstreams)
	assert.Equal(t, []string{"company-tools"}, snapshot.AggregatorsReferencing("github-mcp"))
	assert.Equal(t, []string{"company-tools"}, snapshot.AggregatorsReferencing("orders-mcp"))
}

func TestComputeMCPAggregationOmitsAggregatedProxyNotLoadedWithWarning(t *testing.T) {
	hook := log.GetTestHook(t)

	githubMCP := mcpManagedTestSpec("github-mcp")
	githubMCP.OrgID = "acme"
	globex := mcpManagedTestSpec("globex-mcp")
	globex.OrgID = "globex"
	other := mcpAggregatorSpec("other-tools", "acme", aggregated("github-mcp", "github"))
	companyTools := mcpAggregatorSpec("company-tools", "acme",
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
		aggregated("globex-mcp", "globex"),
		aggregated("other-tools", "other"),
	)

	snapshot := computeMCPAggregation([]*APISpec{githubMCP, globex, other, companyTools})

	agg, ok := snapshot.Lookup("company-tools")
	require.True(t, ok)
	assert.Equal(t, []mcpaggregator.Upstream{{APIID: "github-mcp", Alias: "github"}}, agg.Upstreams)
	assert.Equal(t, []string{"company-tools"}, snapshot.AggregatorsReferencing("orders-mcp"),
		"references are kept for unloaded aggregated proxies")

	warnings := mcpAggregatorWarnings(hook)
	require.Len(t, warnings, 3)
	assert.Equal(t, "company-tools", warnings[0].Data["aggregator_api_id"])
	assert.Equal(t, "orders-mcp", warnings[0].Data["upstream_api_id"])
	assert.Equal(t, "orders", warnings[0].Data["alias"])
	assert.Equal(t, "not loaded on this gateway", warnings[0].Data["reason"])
	assert.Equal(t, "belongs to a different organisation", warnings[1].Data["reason"])
	assert.Equal(t, "is an aggregator", warnings[2].Data["reason"])
}

func TestLoadAppsBuildsMCPAggregatorIndex(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	githubMCP := mcpManagedTestSpec("github-mcp")
	githubMCP.OrgID = "acme"
	githubMCP.UseKeylessAccess = true
	companyTools := mcpAggregatorSpec("company-tools", "acme", aggregated("github-mcp", "github"))
	companyTools.UseKeylessAccess = true

	ts.Gw.LoadAPI(githubMCP, companyTools)

	assert.True(t, ts.Gw.mcpAggregatorIndex.Allows("company-tools", "github-mcp"))
	assert.Equal(t, []string{"company-tools"}, ts.Gw.mcpAggregatorIndex.AggregatorsReferencing("github-mcp"))

	ts.Gw.LoadAPI(githubMCP)
	assert.False(t, ts.Gw.mcpAggregatorIndex.Allows("company-tools", "github-mcp"))
	assert.Empty(t, ts.Gw.mcpAggregatorIndex.AggregatorsReferencing("github-mcp"))
}

func TestDeleteMCPProxyReferencedByAggregatorIsRejected(t *testing.T) {
	appPath := t.TempDir()
	gw := newMCPTestGateway(t, appPath)
	githubMCP := mcpManagedTestSpec("github")
	githubMCP.OrgID = "acme"
	companyTools := mcpAggregatorSpec("company-tools", "acme", aggregated("github", "github"))
	gw.apisByID["github"] = githubMCP
	gw.apisByID["company-tools"] = companyTools
	gw.mcpAggregatorIndex.Set(computeMCPAggregation([]*APISpec{githubMCP, companyTools}))

	fs := afero.NewOsFs()
	require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, "github.json"), []byte("{}"), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, "github-mcp.json"), []byte("{}"), 0644))

	t.Run("MCP management API", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/tyk/mcps/github", nil), map[string]string{"apiID": "github"})
		w := httptest.NewRecorder()

		gw.mcpDeleteHandler(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), `API \"github\" is referenced by MCP aggregators: company-tools`)
		assert.FileExists(t, filepath.Join(appPath, "github-mcp.json"))
	})

	t.Run("generic API", func(t *testing.T) {
		resp, code := gw.handleDeleteAPI("github")

		assert.Equal(t, http.StatusConflict, code)
		msg, ok := resp.(apiStatusMessage)
		require.True(t, ok)
		assert.Equal(t, `API "github" is referenced by MCP aggregators: company-tools`, msg.Message)
		assert.FileExists(t, filepath.Join(appPath, "github-mcp.json"))
	})

	t.Run("allowed once no aggregator references it", func(t *testing.T) {
		gw.mcpAggregatorIndex.Set(computeMCPAggregation([]*APISpec{githubMCP}))
		req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/tyk/mcps/github", nil), map[string]string{"apiID": "github"})
		w := httptest.NewRecorder()

		gw.mcpDeleteHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.NoFileExists(t, filepath.Join(appPath, "github-mcp.json"))
	})
}

// mcpAggregatorDeleteGuardGateway loads MCP proxies "github" and "orders" and
// aggregator "company-tools" over both, with their files in the app path, as
// if the Gateway API had created them and the gateway had reloaded since.
func mcpAggregatorDeleteGuardGateway(t *testing.T) (*Gateway, string) {
	t.Helper()

	appPath := t.TempDir()
	gw := newMCPTestGateway(t, appPath)
	github := mcpManagedTestSpec("github")
	github.OrgID = "acme"
	orders := mcpManagedTestSpec("orders")
	orders.OrgID = "acme"
	companyTools := mcpAggregatorSpec("company-tools", "acme", aggregated("github", "github"), aggregated("orders", "orders"))
	specs := []*APISpec{github, orders, companyTools}
	fs := afero.NewOsFs()
	for _, spec := range specs {
		gw.apisByID[spec.APIID] = spec
		require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, spec.APIID+".json"), []byte("{}"), 0644))
		require.NoError(t, afero.WriteFile(fs, filepath.Join(appPath, spec.APIID+"-mcp.json"), []byte("{}"), 0644))
	}
	gw.mcpAggregatorIndex.Set(computeMCPAggregation(specs))
	return gw, appPath
}

func deleteMCPProxyThroughAPI(gw *Gateway, apiID string) *httptest.ResponseRecorder {
	req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/tyk/mcps/"+apiID, nil), map[string]string{"apiID": apiID})
	w := httptest.NewRecorder()
	gw.mcpDeleteHandler(w, req)
	return w
}

func writeMCPAggregatorThroughAPI(t *testing.T, gw *Gateway, method string, doc *oas.OAS) {
	t.Helper()

	body, err := json.Marshal(doc)
	require.NoError(t, err)
	apiID := doc.GetTykExtension().Info.ID
	req := mux.SetURLVars(httptest.NewRequest(method, "/tyk/mcps/"+apiID, bytes.NewReader(body)), map[string]string{"apiID": apiID})
	w := httptest.NewRecorder()
	if method == http.MethodPost {
		gw.mcpCreateHandler(w, req)
	} else {
		gw.mcpUpdateHandler(w, req)
	}
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestDeleteMCPProxyAllowedOnceItsAggregatorIsDeletedBeforeReload(t *testing.T) {
	gw, _ := mcpAggregatorDeleteGuardGateway(t)

	w := deleteMCPProxyThroughAPI(gw, "company-tools")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = deleteMCPProxyThroughAPI(gw, "orders")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestDeleteMCPProxyAllowedOnceItsAggregatorNoLongerReferencesItBeforeReload(t *testing.T) {
	gw, _ := mcpAggregatorDeleteGuardGateway(t)

	writeMCPAggregatorThroughAPI(t, gw, http.MethodPut, mcpAggregatorOAS("company-tools", "acme", aggregated("github", "github")))

	w := deleteMCPProxyThroughAPI(gw, "orders")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = deleteMCPProxyThroughAPI(gw, "github")
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `API \"github\" is referenced by MCP aggregators: company-tools`)
}

func TestDeleteMCPProxyRejectedWhileAnAggregatorCreatedBeforeReloadReferencesIt(t *testing.T) {
	gw, _ := mcpAggregatorDeleteGuardGateway(t)

	writeMCPAggregatorThroughAPI(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme", aggregated("github", "github")))
	writeMCPAggregatorThroughAPI(t, gw, http.MethodPut, mcpAggregatorOAS("company-tools", "acme", aggregated("orders", "orders")))

	w := deleteMCPProxyThroughAPI(gw, "github")
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `API \"github\" is referenced by MCP aggregators: all-tools`)
}
