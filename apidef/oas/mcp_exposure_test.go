package oas

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMCP_FillExtractRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   MCP
	}{
		{name: "default-empty", in: MCP{}},
		{name: "enabled-expose-all", in: MCP{Enabled: true, Curation: "expose-all"}},
		{name: "enabled-strict-opt-in", in: MCP{Enabled: true, Curation: "strict-opt-in"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var api apidef.APIDefinition
			tc.in.ExtractTo(&api)

			var got MCP
			got.Fill(api)

			assert.Equal(t, tc.in, got)
		})
	}
}

func TestServer_MCPRoundTrip(t *testing.T) {
	t.Parallel()

	original := Server{
		MCP: &MCP{Enabled: true, Curation: "strict-opt-in"},
	}

	var api apidef.APIDefinition
	original.ExtractTo(&api)

	assert.True(t, api.MCPExposure.Enabled)
	assert.Equal(t, "strict-opt-in", api.MCPExposure.Curation)
	assert.True(t, api.IsMCPExposed())

	var got Server
	got.Fill(api)

	require.NotNil(t, got.MCP)
	assert.Equal(t, original.MCP, got.MCP)
}

func TestServer_MCPOmittedWhenDisabled(t *testing.T) {
	t.Parallel()

	// Disabled with no curation should round-trip to nil MCP so the
	// omitempty marshalling keeps the OAS document clean.
	original := Server{MCP: &MCP{}}

	var api apidef.APIDefinition
	original.ExtractTo(&api)

	var got Server
	got.Fill(api)

	assert.Nil(t, got.MCP)
}

func TestSanitizeToolName(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":               "",
		"getOrder":       "getOrder",
		"get order":      "get_order",
		"get  -- order":  "get_--_order", // dashes are valid MCP tool-name chars
		"___strip___":    "strip",
		"/v1/orders/{x}": "v1_orders_x",
	}

	for in, want := range cases {
		assert.Equal(t, want, SanitizeToolName(in), "input=%q", in)
	}
}

func TestAdapterAPIIDHelpers(t *testing.T) {
	t.Parallel()

	rest := "abc123"
	adapter := AdapterAPIID(rest)
	assert.Equal(t, "abc123__mcp-server", adapter)
	assert.True(t, IsAdapterAPIID(adapter))
	assert.False(t, IsAdapterAPIID(rest))
	assert.False(t, IsAdapterAPIID(AdapterAPIIDSuffix))
	assert.Equal(t, rest, AdapterSourceAPIID(adapter))
	assert.Equal(t, "", AdapterSourceAPIID(rest))
	assert.Equal(t, "abc123__mcp-server", AdapterLoopHost(rest))
	assert.Equal(t, "tyk://abc123__mcp-server", AdapterLoopURL(rest))
}

func makeTestOAS(t *testing.T) *OAS {
	t.Helper()

	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "Orders", Version: "1.0"},
		Paths:   openapi3.NewPaths(),
	}

	doc.Paths.Set("/orders/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getOrder",
			Summary:     "fetch an order by id",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name:     "id",
					In:       openapi3.ParameterInPath,
					Required: true,
					Schema:   &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				}},
				{Value: &openapi3.Parameter{
					Name:   "verbose",
					In:     openapi3.ParameterInQuery,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"boolean"}}},
				}},
			},
		},
	})

	doc.Paths.Set("/orders", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "createOrder",
			Summary:     "create a new order",
			RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
				Required: true,
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"object"},
						Properties: openapi3.Schemas{
							"sku":    &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							"amount": &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
						},
						Required: []string{"sku"},
					}}},
				},
			}},
		},
	})

	return &OAS{T: *doc}
}

func TestDeriveSourceTools_ExposeAll(t *testing.T) {
	t.Parallel()

	tools, warns, err := DeriveSourceTools(makeTestOAS(t), nil)
	require.NoError(t, err)
	assert.Empty(t, warns)
	require.Len(t, tools, 2)

	// Deterministic alphabetical order.
	assert.Equal(t, "createOrder", tools[0].Name)
	assert.Equal(t, "getOrder", tools[1].Name)

	get := tools[1]
	assert.Equal(t, "GET", get.Method)
	assert.Equal(t, "/orders/{id}", get.PathTemplate)
	assert.Equal(t, "path", get.ParamLocations["id"])
	assert.Equal(t, "query", get.ParamLocations["verbose"])

	create := tools[0]
	assert.Equal(t, "POST", create.Method)
	assert.Equal(t, "/orders", create.PathTemplate)
	assert.Equal(t, "body.sku", create.ParamLocations["sku"])
	assert.Equal(t, "body.amount", create.ParamLocations["amount"])
}

func TestDeriveSourceTools_StrictOptIn(t *testing.T) {
	t.Parallel()

	curation := MCPPrimitives{"getOrder": &MCPPrimitive{}}

	tools, _, err := DeriveSourceTools(makeTestOAS(t), curation)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "getOrder", tools[0].Name)
}

func TestDeriveSourceTools_MissingOperationID(t *testing.T) {
	t.Parallel()

	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "X", Version: "1"},
		Paths:   openapi3.NewPaths(),
	}
	doc.Paths.Set("/x", &openapi3.PathItem{Get: &openapi3.Operation{}})

	tools, warns, err := DeriveSourceTools(&OAS{T: *doc}, nil)
	require.NoError(t, err)
	assert.Empty(t, tools)
	require.Len(t, warns, 1)
	assert.Contains(t, warns[0].Reason, "missing operationId")
}

func TestDeriveSourceTools_NilOAS(t *testing.T) {
	t.Parallel()

	_, _, err := DeriveSourceTools(nil, nil)
	assert.Error(t, err)
}
