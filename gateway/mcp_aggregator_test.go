package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func mcpAggregatorOAS(apiID, orgID string, upstreams ...oas.TykMCPAggregatorUpstream) *oas.OAS {
	doc := &oas.OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    apiID,
			OrgID: orgID,
			Name:  apiID,
			State: oas.State{Active: true},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/" + apiID + "/"},
		},
		Upstream: oas.Upstream{URL: oas.MCPAggregatorTargetURL},
	})
	doc.SetTykMCPAggregatorExtension(&oas.TykMCPAggregator{Upstreams: upstreams})
	return doc
}

func mcpAggregatorSpec(apiID, orgID string, upstreams ...oas.TykMCPAggregatorUpstream) *APISpec {
	doc := mcpAggregatorOAS(apiID, orgID, upstreams...)
	api := &apidef.APIDefinition{}
	doc.ExtractTo(api)
	api.APIID = apiID
	api.OrgID = orgID
	api.IsOAS = true
	api.MarkAsMCP()
	return &APISpec{APIDefinition: api, OAS: *doc}
}

func aggregated(apiID, alias string) oas.TykMCPAggregatorUpstream {
	return oas.TykMCPAggregatorUpstream{APIID: apiID, Alias: alias}
}

func TestDecodeMCPProxyDefinitionClassifiesAggregatorAsMCPManaged(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(mcpAggregatorOAS("company-tools", "org-1", aggregated("orders-mcp", "orders")))
	require.NoError(t, err)

	parsed, err := decodeMCPProxyDefinition(bytes.NewReader(body))
	require.NoError(t, err)

	assert.True(t, parsed.apiDef.IsMCPAggregator())
	assert.True(t, parsed.apiDef.IsMCP())
	assert.True(t, parsed.apiDef.IsMCPManaged())
	assert.False(t, parsed.apiDef.IsPairedMCPAdapterProxy())
	require.NotNil(t, parsed.oasObj.GetTykMCPAggregatorExtension())
	assert.Equal(t, []oas.TykMCPAggregatorUpstream{aggregated("orders-mcp", "orders")}, parsed.oasObj.GetTykMCPAggregatorExtension().Upstreams)
}

type mcpAggregatorAdmissionResult struct {
	code       int
	body       string
	nextCalled bool
}

func postMCPAggregatorThroughValidateMCP(t *testing.T, gw *Gateway, method string, doc *oas.OAS) mcpAggregatorAdmissionResult {
	t.Helper()

	body, err := json.Marshal(doc)
	require.NoError(t, err)
	return postRawMCPAggregatorThroughValidateMCP(t, gw, method, body)
}

func postRawMCPAggregatorThroughValidateMCP(t *testing.T, gw *Gateway, method string, body []byte) mcpAggregatorAdmissionResult {
	t.Helper()

	result := mcpAggregatorAdmissionResult{}
	handler := gw.validateMCP(func(w http.ResponseWriter, _ *http.Request) {
		result.nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(method, "/tyk/mcps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	result.code = w.Code
	result.body = w.Body.String()
	return result
}

// mcpAggregatorAdmissionGateway loads one API-to-MCP proxy ("orders-mcp" over
// REST source "orders-rest"), one remote MCP proxy ("github-mcp"), one REST
// API ("payments-rest"), one aggregator ("company-tools") and one MCP proxy
// owned by another organisation ("globex-orders-mcp").
func mcpAggregatorAdmissionGateway(t *testing.T) *Gateway {
	t.Helper()

	gw := newMCPTestGateway(t)
	ordersREST := restSourceSpec("orders-rest", "acme", true)
	ordersMCP := pairedMCPProxySpec("orders-mcp", "acme", "orders-rest", nil)
	githubMCP := mcpManagedTestSpec("github-mcp")
	githubMCP.OrgID = "acme"
	payments := restSourceSpec("payments-rest", "acme", true)
	companyTools := mcpAggregatorSpec("company-tools", "acme", aggregated("orders-mcp", "orders"))
	globex := mcpManagedTestSpec("globex-orders-mcp")
	globex.OrgID = "globex"

	for _, spec := range []*APISpec{ordersREST, ordersMCP, githubMCP, payments, companyTools, globex} {
		gw.apisByID[spec.APIID] = spec
	}
	return gw
}

func TestMCPAggregatorAcceptsMixedAggregatedProxyTypes(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
	))

	assert.Equal(t, http.StatusOK, res.code, res.body)
	assert.True(t, res.nextCalled)
}

func TestMCPAggregatorCreateSavesAggregatorAsMCPProxy(t *testing.T) {
	appPath := t.TempDir()
	gw := mcpAggregatorAdmissionGateway(t)
	gw.SetConfig(func() config.Config { c := gw.GetConfig(); c.AppPath = appPath; return c }())

	body, err := json.Marshal(mcpAggregatorOAS("all-tools", "acme",
		aggregated("orders-mcp", "orders"),
		aggregated("github-mcp", "github"),
	))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	gw.validateMCP(gw.mcpCreateHandler).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"action":"added"`)
	saved, err := os.ReadFile(filepath.Join(appPath, "all-tools-mcp.json"))
	require.NoError(t, err)
	assert.Contains(t, string(saved), `"x-tyk-mcp-aggregator"`)
	assert.Contains(t, string(saved), `"alias": "github"`)
}

func TestMCPAggregatorRequiresAtLeastOneAggregatedProxy(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme"))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, "at least one aggregated MCP proxy is required")
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsUnknownAggregatedProxy(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("orders-mcp", "orders"),
		aggregated("does-not-exist", "missing"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `aggregated MCP proxy \"does-not-exist\" not found`)
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsNonMCPAggregatedProxy(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("payments-rest", "payments"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `aggregated MCP proxy \"payments-rest\" is not an MCP proxy: aggregated MCP proxies must be MCP proxies`)
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsAggregatorAsAggregatedProxy(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("company-tools", "company"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `aggregated MCP proxy \"company-tools\" is an aggregator: an aggregator cannot aggregate another aggregator`)
	assert.False(t, res.nextCalled)

	t.Run("including itself on update", func(t *testing.T) {
		res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPut, mcpAggregatorOAS("company-tools", "acme",
			aggregated("company-tools", "self"),
		))

		assert.Equal(t, http.StatusBadRequest, res.code)
		assert.Contains(t, res.body, "an aggregator cannot aggregate another aggregator")
	})
}

func TestMCPAggregatorRejectsAggregatedProxyNotLoadedOnThisGateway(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	// "eu-orders-mcp" is deployed only to another gateway, so this gateway
	// has never loaded it.
	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("eu-orders-mcp", "orders"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `aggregated MCP proxy \"eu-orders-mcp\" not found: it is not loaded on this gateway and must be deployed to the same gateway as the aggregator`)
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsAggregatedProxyFromAnotherOrg(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("globex-orders-mcp", "orders"),
	))

	assert.Equal(t, http.StatusForbidden, res.code)
	assert.Contains(t, res.body, `aggregated MCP proxy \"globex-orders-mcp\" belongs to a different organisation`)
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsDuplicateAlias(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("github-mcp", "github"),
		aggregated("orders-mcp", "github"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, "aliases must be unique")
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsInvalidAlias(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("github-mcp", "GitHub Prod"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `alias \"GitHub Prod\" is invalid: aliases may contain only lowercase letters, digits and hyphens`)
	assert.False(t, res.nextCalled)
}

func TestMCPAggregatorRejectsEmptyToolSelection(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	body, err := json.Marshal(mcpAggregatorOAS("all-tools", "acme", aggregated("orders-mcp", "orders")))
	require.NoError(t, err)
	body = bytes.Replace(body, []byte(`"alias":"orders"`), []byte(`"alias":"orders","tools":[]`), 1)

	res := postRawMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, body)

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, "select at least one tool or omit the field")
}

func TestHandleAddApiOASRejectsMCPAggregatorWithUnknownAggregatedProxy(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	body, err := json.Marshal(mcpAggregatorOAS("all-tools", "acme", aggregated("does-not-exist", "missing")))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/tyk/apis/oas", bytes.NewReader(body))

	resp, code := gw.handleAddApi(req, afero.NewMemMapFs(), true)

	require.Equal(t, http.StatusBadRequest, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, `aggregated MCP proxy "does-not-exist" not found`)
}

func TestMCPAggregatorRejectsSameAggregatedProxyListedTwice(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	res := postMCPAggregatorThroughValidateMCP(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme",
		aggregated("github-mcp", "github"),
		aggregated("github-mcp", "github-2"),
	))

	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, `apiId \"github-mcp\" is duplicated: each aggregated MCP proxy may be listed only once`)
	assert.False(t, res.nextCalled)
}

func TestClassifyMCPAggregatorUpstream(t *testing.T) {
	gw := mcpAggregatorAdmissionGateway(t)

	tests := []struct {
		apiID  string
		want   mcpAggregatorUpstreamStatus
		reason string
	}{
		{"orders-mcp", mcpAggregatorUpstreamAdmitted, ""},
		{"github-mcp", mcpAggregatorUpstreamAdmitted, ""},
		{"does-not-exist", mcpAggregatorUpstreamNotLoaded, "not loaded on this gateway"},
		{"globex-orders-mcp", mcpAggregatorUpstreamOtherOrg, "belongs to a different organisation"},
		{"company-tools", mcpAggregatorUpstreamIsAggregator, "is an aggregator"},
		{"payments-rest", mcpAggregatorUpstreamNotMCP, "is not an MCP proxy"},
	}
	for _, tt := range tests {
		status := classifyMCPAggregatorUpstream("acme", gw.apisByID[tt.apiID])
		assert.Equal(t, tt.want, status, tt.apiID)
		assert.Equal(t, tt.reason, status.String(), tt.apiID)
		msg, _ := status.admissionError(tt.apiID)
		assert.Equal(t, tt.want == mcpAggregatorUpstreamAdmitted, msg == "", tt.apiID)
	}
}
