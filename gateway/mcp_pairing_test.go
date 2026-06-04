package gateway

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
)

func TestComputeMCPPairing(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)

	snapshot, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.NoError(t, err)

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, "rest-1__mcp-server", source.AdapterAPIID)
	assert.Equal(t, []string{"proxy-1"}, source.CallerProxyAPIIDs)
}

func TestComputeMCPPairing_CrossOrgRefused(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-rest", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-proxy", "rest-1", nil)

	_, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-org")
}

func TestReferencedMCPAdapterRESTIDs_AreProxyDriven(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	unreferenced := restSourceSpec("rest-2", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)

	snapshot, err := computeMCPPairing([]*APISpec{rest, unreferenced, proxy})
	require.NoError(t, err)

	assert.Equal(t, []string{"rest-1"}, snapshot.ReferencedRESTAPIIDs())
}

func TestReferencedMCPAdapterRESTIDs_RemainsAfterOneProxyRemoved(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-remaining", "org-1", "rest-1", nil)

	snapshot, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.NoError(t, err)

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-remaining"}, source.CallerProxyAPIIDs)
	assert.False(t, snapshot.AllowsCaller(pairing.CanonicalAdapterAPIID("rest-1"), "proxy-removed"))
}

func TestComputeMCPPairing_DuplicateProxyTargetsAllowed(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy1 := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	proxy2 := pairedMCPProxySpec("proxy-2", "org-1", "rest-1", nil)

	snapshot, err := computeMCPPairing([]*APISpec{rest, proxy1, proxy2})
	require.NoError(t, err)

	source, ok := snapshot.LookupSource("rest-1")
	require.True(t, ok)
	assert.Equal(t, []string{"proxy-1", "proxy-2"}, source.CallerProxyAPIIDs)
}

func TestDeriveMCPAdapterCatalogue_BuildsProxySpecificToolViewsAndUnion(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy1 := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Description: "orders visible to proxy one", Allow: boolPtr(true)},
		},
	})
	proxy2 := pairedMCPProxySpec("proxy-2", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Name: "make_order", Description: "orders visible to proxy two", Allow: boolPtr(true)},
		},
	})

	catalogue, err := deriveMCPAdapterCatalogue(rest, []*APISpec{proxy1, proxy2})
	require.NoError(t, err)

	assert.Equal(t, []string{"make_order", "orders"}, derivedToolNames(catalogue.unionTools))
	assert.Equal(t, []string{"orders"}, catalogue.toolViews["proxy-1"].ToolNames())
	assert.Equal(t, []string{"make_order"}, catalogue.toolViews["proxy-2"].ToolNames())
	assert.Equal(t, "orders visible to proxy one", catalogue.toolViews["proxy-1"].Tools[0].Description)
	assert.Equal(t, "orders visible to proxy two", catalogue.toolViews["proxy-2"].Tools[0].Description)
}

func TestBuildAdapterSpec_ReusesSDKAdapterAndUpdatesTools(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)

	first, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, nil)
	require.NoError(t, err)
	require.True(t, first.IsSyntheticMCPAdapter())
	require.NotNil(t, first.MCPSDKAdapter)
	assert.Equal(t, "rest-1__mcp-server", first.APIID)
	assert.Equal(t, "rest-1", first.MCPAdapterSourceRESTAPIID)
	assert.Equal(t, []string{"proxy-1"}, first.MCPAllowedCallerProxyAPIIDs)

	rest.OAS.Paths.Set("/orders", &openapi3.PathItem{
		Get: &openapi3.Operation{OperationID: "list_orders", Summary: "updated list orders"},
	})

	reused, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, first)
	require.NoError(t, err)
	assert.Same(t, first.MCPSDKAdapter, reused.MCPSDKAdapter)
	tool, ok := reused.MCPToolViews["proxy-1"].ToolByName("list_orders")
	require.True(t, ok)
	assert.Equal(t, "updated list orders", tool.Description)
}

func TestSynthesizeMCPAdapterSpecs_AppendsHiddenInternalAdapters(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)

	specs, snapshot, err := synthesizeMCPAdapterSpecs([]*APISpec{rest, proxy}, nil)
	require.NoError(t, err)

	require.Len(t, specs, 3)
	adapterSpec := specs[2]
	assert.True(t, adapterSpec.IsSyntheticMCPAdapter())
	assert.True(t, adapterSpec.Internal)
	assert.Equal(t, "rest-1__mcp-server", adapterSpec.APIID)
	assert.False(t, mcpManaged(adapterSpec))
	assert.True(t, snapshot.AllowsCaller("rest-1__mcp-server", "proxy-1"))
}

func pairedMCPProxySpec(proxyID, orgID, restID string, ext *oas.TykMCPServer) *APISpec {
	doc := pairedMCPProxyOAS(proxyID, orgID, restID)
	if ext != nil {
		doc.SetTykMCPServerExtension(ext)
	}
	api := &apidef.APIDefinition{}
	doc.ExtractTo(api)
	api.APIID = proxyID
	api.OrgID = orgID
	api.IsOAS = true

	return &APISpec{
		APIDefinition: api,
		OAS:           *doc,
	}
}

func derivedToolNames(tools []oas.DerivedTool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
