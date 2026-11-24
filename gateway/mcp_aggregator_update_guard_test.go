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

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

func mcpAggregatorUpdateGuardGateway(t *testing.T) *Gateway {
	t.Helper()
	gw := newMCPTestGateway(t, t.TempDir())
	githubMCP := mcpManagedTestSpec("github")
	githubMCP.OrgID = "acme"
	companyTools := mcpAggregatorSpec("company-tools", "acme", aggregated("github", "github"))
	gw.apisByID["github"] = githubMCP
	gw.apisByID["company-tools"] = companyTools
	gw.mcpAggregatorIndex.Set(computeMCPAggregation([]*APISpec{githubMCP, companyTools}))
	return gw
}

func mcpProxyUpdate(orgID string, mcp bool) (*apidef.APIDefinition, *oas.OAS) {
	doc := mcpRuntimeDoc("github", "https://example.com/mcp")
	doc.GetTykExtension().Info.OrgID = orgID
	api := &apidef.APIDefinition{}
	doc.ExtractTo(api)
	if mcp {
		api.MarkAsMCP()
	}
	return api, doc
}

func TestMCPAggregatorUpdateConflict(t *testing.T) {
	gw := mcpAggregatorUpdateGuardGateway(t)

	t.Run("an update that keeps the proxy usable is accepted", func(t *testing.T) {
		api, doc := mcpProxyUpdate("acme", true)
		msg, code := gw.mcpAggregatorUpdateConflict("github", api, doc)
		assert.Empty(t, msg)
		assert.Zero(t, code)
	})

	t.Run("moving the proxy to another organisation is rejected", func(t *testing.T) {
		api, doc := mcpProxyUpdate("globex", true)
		msg, code := gw.mcpAggregatorUpdateConflict("github", api, doc)
		assert.Equal(t, http.StatusConflict, code)
		assert.Equal(t, `API "github" is referenced by MCP aggregators: company-tools; after this update it belongs to a different organisation and could no longer be aggregated`, msg)
	})

	t.Run("turning the proxy into a non-MCP API is rejected", func(t *testing.T) {
		api, doc := mcpProxyUpdate("acme", false)
		msg, code := gw.mcpAggregatorUpdateConflict("github", api, doc)
		assert.Equal(t, http.StatusConflict, code)
		assert.Contains(t, msg, "is not an MCP proxy")
	})

	t.Run("turning the proxy into an aggregator is rejected", func(t *testing.T) {
		updated := mcpAggregatorSpec("github", "acme", aggregated("other", "other"))
		msg, code := gw.mcpAggregatorUpdateConflict("github", updated.APIDefinition, &updated.OAS)
		assert.Equal(t, http.StatusConflict, code)
		assert.Contains(t, msg, "is an aggregator")
	})

	t.Run("an API no aggregator references is not checked", func(t *testing.T) {
		api, doc := mcpProxyUpdate("globex", false)
		msg, code := gw.mcpAggregatorUpdateConflict("payments", api, doc)
		assert.Empty(t, msg)
		assert.Zero(t, code)
	})
}

func TestUpdateMCPProxyReferencedByAggregatorIntoAggregatorIsRejected(t *testing.T) {
	gw := mcpAggregatorUpdateGuardGateway(t)

	body, err := json.Marshal(mcpAggregatorOAS("github", "acme", aggregated("other", "other")))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/tyk/mcps/github", bytes.NewReader(body))

	resp, code := gw.handleUpdateMCP("github", req, afero.NewMemMapFs())

	assert.Equal(t, http.StatusConflict, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, `API "github" is referenced by MCP aggregators: company-tools`)
}

func TestUpdateMCPProxyReferencedByAggregatorThroughOASEndpointIsRejected(t *testing.T) {
	gw := mcpAggregatorUpdateGuardGateway(t)
	gw.apisByID["github"].IsOAS = true

	_, doc := mcpProxyUpdate("acme", false)
	body, err := json.Marshal(doc)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/tyk/apis/oas/github", bytes.NewReader(body))

	resp, code := gw.handleUpdateApi("github", req, afero.NewMemMapFs(), true)

	assert.Equal(t, http.StatusConflict, code)
	msg, ok := resp.(apiStatusMessage)
	require.True(t, ok)
	assert.Contains(t, msg.Message, "is not an MCP proxy")
}
