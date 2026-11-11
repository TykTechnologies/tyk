package gateway

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
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
