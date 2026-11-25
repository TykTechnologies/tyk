package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/test"
)

func mcpAggregatorRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return httptest.NewRequest(method, path, bytes.NewReader(raw))
}

func TestMCPAggregatorUpdateWithAMismatchedAPIIDProbesNoUpstream(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	before := len(github.observed())

	_, err := ts.Run(t, test.TestCase{
		AdminAuth: true, Method: http.MethodPut, Path: "/tyk/mcps/company-tools",
		Data:      mcpAggregatorOAS("other-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")),
		Code:      http.StatusBadRequest,
		BodyMatch: "Request APIID does not match",
	})
	require.NoError(t, err)
	assert.Len(t, github.observed(), before, "a request rejected by its API ID checks never reaches an upstream")
}

func TestMCPAggregatorCreateProbesUnderItsFinalAPIID(t *testing.T) {
	down := newLatestOnlyMCPUpstream(t, "list_issues")
	down.Close()
	ts := startMCPAggregatorCompatTest(t, down.URL)
	hook := log.GetTestHook(t)
	doc := mcpAggregatorOAS("", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github"))
	doc.Info.Title = "company-tools"
	doc.GetTykExtension().Info.Name = "company-tools"
	doc.GetTykExtension().Server.ListenPath.Value = "/company-tools/"

	resp, err := ts.Run(t, test.TestCase{
		AdminAuth: true, Method: http.MethodPost, Path: "/tyk/mcps",
		Data: doc,
		Code: http.StatusOK,
	})
	require.NoError(t, err)
	var created apiModifyKeySuccess
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.NotEmpty(t, created.Key)
	warnings := mcpAggregatorVersionCheckWarnings(hook, "github-mcp")
	require.Len(t, warnings, 1)
	assert.Equal(t, created.Key, warnings[0].Data["aggregator_api_id"], "the probe runs under the generated API ID")
}

func TestMCPAggregatorUpdateDoesNotReprobeAdmittedUpstreams(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	// github-mcp was admitted, then its upstream dropped 2026-07-28.
	github.setVersions(mcp.LegacyFallbackProtocolVersion)
	before := len(github.observed())

	renamed := mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github"))
	renamed.GetTykExtension().Info.Name = "Company tools v2"
	resp, code := ts.Gw.handleUpdateMCP("company-tools", mcpAggregatorRequest(t, http.MethodPut, "/tyk/mcps/company-tools", renamed), afero.NewMemMapFs())

	require.Equal(t, http.StatusOK, code, resp)
	assert.Len(t, github.observed(), before, "an aggregated proxy the loaded aggregator admits is not probed again")
}

func TestMCPAggregatorUpdateProbesOnlyNewUpstreams(t *testing.T) {
	github := newLatestOnlyMCPUpstream(t, "list_issues")
	legacy := newLegacyOnlyMCPUpstream(t, "list_issues")
	ts := startMCPAggregatorCompatTest(t, github.URL)
	legacySpec := githubMCPProxyRuntimeSpec(legacy.URL)
	legacySpec.APIID, legacySpec.Name, legacySpec.Proxy.ListenPath = "legacy-mcp", "legacy-mcp", "/legacy-mcp/"
	ts.Gw.LoadAPI(githubMCPProxyRuntimeSpec(github.URL), legacySpec, companyToolsRuntimeSpec(aggregated("github-mcp", "github")))
	before := len(github.observed())

	resp, code := ts.Gw.handleUpdateMCP("company-tools", mcpAggregatorRequest(t, http.MethodPut, "/tyk/mcps/company-tools",
		mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github"), aggregated("legacy-mcp", "legacy"))), afero.NewMemMapFs())

	require.Equal(t, http.StatusBadRequest, code, resp)
	assert.Contains(t, resp.(apiStatusMessage).Message, `aggregated MCP proxy "legacy-mcp" does not support MCP version 2026-07-28`)
	assert.Len(t, github.observed(), before, "only the added aggregated proxy is probed")
}

// discoverHangsLegacyListUpstream never answers server/discover and answers
// tools/list as a session-first legacy server does.
func discoverHangsLegacyListUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if !decodeMCPTestRequest(w, r, &req) {
			return
		}
		if req.Method == mcp.MethodServerDiscover {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Mcp-Session-Id header is required"},"id":null}`)); err != nil {
			t.Errorf("w.Write: %v", err)
		}
	}))
	t.Cleanup(func() { close(release); s.Close() })
	return s
}

func TestMCPAggregatorProbeGivesToolsListItsOwnTimeout(t *testing.T) {
	ts := startMCPAggregatorCompatTest(t, discoverHangsLegacyListUpstream(t).URL)
	ts.Gw.SetConfig(func() config.Config { c := ts.Gw.GetConfig(); c.ProxyDefaultTimeout = 1; return c }())

	res := postMCPAggregatorThroughValidateMCP(t, ts.Gw, http.MethodPost, mcpAggregatorOAS("company-tools", mcpAggregatorRuntimeOrg, aggregated("github-mcp", "github")))

	assert.Equal(t, http.StatusBadRequest, res.code, res.body)
	assert.Contains(t, res.body, `aggregated MCP proxy \"github-mcp\" does not support MCP version 2026-07-28: upstream requires a legacy session`,
		"a server/discover that uses its whole timeout leaves tools/list its own")
}
