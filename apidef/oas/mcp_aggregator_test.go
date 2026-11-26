package oas

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func mcpAggregatorTestOAS(upstreamURL string, ext *TykMCPAggregator) *OAS {
	doc := &OAS{T: openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "company-tools", Version: "1.0.0"},
		Paths:   openapi3.NewPaths(),
	}}
	doc.SetTykExtension(&XTykAPIGateway{
		Info:     Info{Name: "company-tools", State: State{Active: true}},
		Server:   Server{ListenPath: ListenPath{Value: "/company-tools/"}},
		Upstream: Upstream{URL: upstreamURL},
	})
	if ext != nil {
		doc.SetTykMCPAggregatorExtension(ext)
	}
	return doc
}

func TestTykMCPAggregatorExtension_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"openapi":"3.0.3",
		"info":{"title":"company-tools","version":"1.0.0"},
		"paths":{},
		"x-tyk-api-gateway":{
			"info":{"name":"company-tools"},
			"upstream":{"url":"tyk://mcp-aggregator"},
			"server":{"listenPath":{"value":"/company-tools/"}}
		},
		"x-tyk-mcp-aggregator":{
			"upstreams":[
				{"apiId":"orders-mcp","alias":"orders","tools":["list_orders"]},
				{"apiId":"github-mcp","alias":"github"}
			]
		}
	}`)

	var doc OAS
	require.NoError(t, json.Unmarshal(raw, &doc))

	ext := doc.GetTykMCPAggregatorExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Upstreams, 2)
	assert.Equal(t, TykMCPAggregatorUpstream{APIID: "orders-mcp", Alias: "orders", Tools: []string{"list_orders"}}, ext.Upstreams[0])
	assert.Equal(t, TykMCPAggregatorUpstream{APIID: "github-mcp", Alias: "github"}, ext.Upstreams[1])
	assert.Nil(t, ext.Upstreams[1].Tools, "omitted tools must stay nil so it means all tools")

	out, err := json.Marshal(&doc)
	require.NoError(t, err)
	assert.JSONEq(t, `{"upstreams":[{"apiId":"orders-mcp","alias":"orders","tools":["list_orders"]},{"apiId":"github-mcp","alias":"github"}]}`,
		string(mustExtensionJSON(t, out, ExtensionTykMCPAggregator)))

	var api apidef.APIDefinition
	doc.ExtractTo(&api)
	api.MarkAsMCP()
	assert.True(t, api.IsMCPAggregator())

	doc.RemoveTykMCPAggregatorExtension()
	assert.Nil(t, doc.GetTykMCPAggregatorExtension())
}

func mustExtensionJSON(t *testing.T, doc []byte, key string) json.RawMessage {
	t.Helper()
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &parsed))
	return parsed[key]
}

func TestMCPAggregatorExtensionPlacement(t *testing.T) {
	t.Parallel()

	valid := &TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{{APIID: "orders-mcp", Alias: "orders"}}}

	t.Run("accepted on an MCP proxy with the aggregator upstream", func(t *testing.T) {
		t.Parallel()
		doc := mcpAggregatorTestOAS(MCPAggregatorTargetURL, valid)
		assert.NoError(t, doc.ValidateForMCP(context.Background()))
	})

	t.Run("rejected on a non-MCP API", func(t *testing.T) {
		t.Parallel()
		doc := mcpAggregatorTestOAS(MCPAggregatorTargetURL, valid)
		err := doc.Validate(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x-tyk-mcp-aggregator is valid only for MCP proxies")
	})

	t.Run("requires the aggregator upstream URL", func(t *testing.T) {
		t.Parallel()
		doc := mcpAggregatorTestOAS("http://mcp.example", valid)
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), `x-tyk-mcp-aggregator requires upstream.url "tyk://mcp-aggregator"`)
	})

	t.Run("aggregator upstream URL without the extension stays an ordinary loop", func(t *testing.T) {
		t.Parallel()
		doc := mcpAggregatorTestOAS(MCPAggregatorTargetURL, nil)
		assert.NoError(t, doc.ValidateForMCP(context.Background()))
		assert.NoError(t, doc.Validate(context.Background()))
	})

	t.Run("cannot be combined with x-tyk-mcp-server", func(t *testing.T) {
		t.Parallel()
		doc := mcpAggregatorTestOAS(MCPAggregatorTargetURL, valid)
		doc.SetTykMCPServerExtension(&TykMCPServer{})
		err := doc.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x-tyk-mcp-aggregator and x-tyk-mcp-server cannot be configured on the same MCP proxy")
	})
}

func TestValidateTykMCPAggregator(t *testing.T) {
	t.Parallel()

	upstream := func(apiID, alias string, tools ...string) TykMCPAggregatorUpstream {
		return TykMCPAggregatorUpstream{APIID: apiID, Alias: alias, Tools: tools}
	}

	tests := []struct {
		name    string
		ext     TykMCPAggregator
		wantErr string
	}{
		{
			name: "valid aliases and tool selections",
			ext: TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{
				upstream("orders-mcp", "orders", "list_orders"),
				upstream("github-mcp", "github-2"),
			}},
		},
		{
			name:    "no aggregated proxies",
			ext:     TykMCPAggregator{},
			wantErr: "x-tyk-mcp-aggregator.upstreams: at least one aggregated MCP proxy is required",
		},
		{
			name:    "missing API ID",
			ext:     TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{upstream(" ", "orders")}},
			wantErr: "x-tyk-mcp-aggregator.upstreams[0].apiId is required",
		},
		{
			name:    "missing alias",
			ext:     TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{upstream("orders-mcp", "")}},
			wantErr: "x-tyk-mcp-aggregator.upstreams[0].alias is required",
		},
		{
			name:    "invalid alias",
			ext:     TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{upstream("github-mcp", "GitHub Prod")}},
			wantErr: `x-tyk-mcp-aggregator.upstreams[0].alias "GitHub Prod" is invalid: aliases may contain only lowercase letters, digits and hyphens`,
		},
		{
			name:    "alias with namespace separator",
			ext:     TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{upstream("github-mcp", "git__hub")}},
			wantErr: "aliases may contain only lowercase letters, digits and hyphens",
		},
		{
			name: "duplicate alias",
			ext: TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{
				upstream("github-mcp", "github"),
				upstream("github-enterprise-mcp", "github"),
			}},
			wantErr: `x-tyk-mcp-aggregator.upstreams[1].alias "github" is duplicated: aliases must be unique`,
		},
		{
			name: "same aggregated proxy listed twice",
			ext: TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{
				upstream("github-mcp", "github"),
				upstream("github-mcp", "github-2"),
			}},
			wantErr: `x-tyk-mcp-aggregator.upstreams[1].apiId "github-mcp" is duplicated: each aggregated MCP proxy may be listed only once`,
		},
		{
			name:    "too many aggregated proxies",
			ext:     TykMCPAggregator{Upstreams: manyMCPAggregatorUpstreams(MaxMCPAggregatorUpstreams + 1)},
			wantErr: "x-tyk-mcp-aggregator.upstreams: at most 50 aggregated MCP proxies are allowed",
		},
		{
			name: "the maximum number of aggregated proxies",
			ext:  TykMCPAggregator{Upstreams: manyMCPAggregatorUpstreams(MaxMCPAggregatorUpstreams)},
		},
		{
			name: "empty tool selection",
			ext: TykMCPAggregator{Upstreams: []TykMCPAggregatorUpstream{
				{APIID: "orders-mcp", Alias: "orders", Tools: []string{}},
			}},
			wantErr: "x-tyk-mcp-aggregator.upstreams[0].tools: select at least one tool or omit the field",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateTykMCPAggregator(&tt.ext)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateForMCPRejectsInvalidMCPAggregator(t *testing.T) {
	t.Parallel()

	doc := mcpAggregatorTestOAS(MCPAggregatorTargetURL, &TykMCPAggregator{})
	err := doc.ValidateForMCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one aggregated MCP proxy is required")
}

func manyMCPAggregatorUpstreams(n int) []TykMCPAggregatorUpstream {
	out := make([]TykMCPAggregatorUpstream, n)
	for i := range out {
		out[i] = TykMCPAggregatorUpstream{APIID: fmt.Sprintf("mcp-%d", i), Alias: fmt.Sprintf("a%d", i)}
	}
	return out
}
