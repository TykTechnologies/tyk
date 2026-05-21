package oas

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTykMCPServerExtension_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"openapi":"3.0.3",
		"info":{"title":"orders proxy","version":"1.0.0"},
		"paths":{},
		"x-tyk-api-gateway":{
			"info":{"name":"orders proxy"},
			"upstream":{"url":"tyk://rest-1__mcp-server"},
			"server":{"listenPath":{"value":"/mcp/","strip":true}}
		},
		"x-tyk-mcp-server":{
			"primitives":[{
				"source":{"operationId":"create_order_source"},
				"name":"create_order",
				"allow":true,
				"description":"Place a new order for a customer",
				"parameters":[{
					"param":"customer_id",
					"name":"customer",
					"description":"Unique identifier of the customer placing the order"
				}]
			}]
		}
	}`)

	var doc OAS
	require.NoError(t, json.Unmarshal(raw, &doc))

	ext := doc.GetTykMCPServerExtension()
	require.NotNil(t, ext)
	require.Len(t, ext.Primitives, 1)
	assert.Equal(t, "create_order_source", ext.Primitives[0].Source.OperationID)
	assert.Equal(t, "create_order", ext.Primitives[0].Name)
	require.NotNil(t, ext.Primitives[0].Allow)
	assert.True(t, *ext.Primitives[0].Allow)
	require.Len(t, ext.Primitives[0].Parameters, 1)
	assert.Equal(t, "customer_id", ext.Primitives[0].Parameters[0].Param)
	assert.Equal(t, "customer", ext.Primitives[0].Parameters[0].Name)

	out, err := json.Marshal(&doc)
	require.NoError(t, err)

	var roundTripped map[string]any
	require.NoError(t, json.Unmarshal(out, &roundTripped))
	require.Contains(t, roundTripped, ExtensionTykMCPServer)
	mcpServer := roundTripped[ExtensionTykMCPServer].(map[string]any)
	require.Len(t, mcpServer["primitives"], 1)
}

func TestTykMCPServerExtension_ValidatePlacement(t *testing.T) {
	t.Parallel()

	doc := newDeriveTestOAS(openapi3.NewPaths())
	doc.SetTykExtension(&XTykAPIGateway{
		Info:     Info{Name: "orders"},
		Upstream: Upstream{URL: "https://example.com/mcp"},
	})
	doc.SetTykMCPServerExtension(&TykMCPServer{})

	err := doc.ValidateForMCP(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), ExtensionTykMCPServer)
	assert.Contains(t, err.Error(), "REST-as-MCP adapter")

	doc.GetTykExtension().Upstream.URL = AdapterLoopURL("rest-1")
	require.NoError(t, doc.ValidateForMCP(context.Background()))

	err = doc.Validate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MCP proxies")
}

func TestDeriveMCPToolView_AppliesExplicitAllowAliasesAndDescriptionOverrides(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "list_orders",
				Summary:     "list orders",
			},
			Post: &openapi3.Operation{
				OperationID: "create_order_source",
				Summary:     "create order",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{
						Name:        "customer_id",
						In:          openapi3.ParameterInQuery,
						Description: "source customer id",
						Schema:      &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
					}},
				},
			},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{
				Source:      TykMCPServerSource{OperationID: "create_order_source"},
				Name:        "create_order",
				Allow:       boolPtr(true),
				Description: "Place a new order for a customer",
				Parameters: []TykMCPServerParameter{
					{
						Param:       "customer_id",
						Name:        "customer",
						Description: "Unique identifier of the customer placing the order",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 1)

	tool := view.Tools[0]
	assert.Equal(t, "create_order_source", tool.OperationID)
	assert.Equal(t, "create_order_source", tool.CanonicalName)
	assert.Equal(t, "create_order", tool.Name)
	assert.Equal(t, "Place a new order for a customer", tool.Description)
	assert.Equal(t, map[string]string{"customer": DerivedParamLocationQuery}, tool.ParamLocations)
	assert.Equal(t, map[string]string{"customer": "customer_id"}, tool.ParamSourceNames)

	props := tool.InputSchema["properties"].(map[string]any)
	customer := props["customer"].(map[string]any)
	assert.Equal(t, "Unique identifier of the customer placing the order", customer["description"])
}

func TestDeriveMCPToolView_PrimitivesWithoutAllowDoNotRestrictExposure(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:  &openapi3.Operation{OperationID: "list_orders", Summary: "list orders"},
			Post: &openapi3.Operation{OperationID: "create_order_source", Summary: "create order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{
				Source:      TykMCPServerSource{OperationID: "create_order_source"},
				Name:        "create_order",
				Description: "Place a new order",
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 2)
	assert.Equal(t, []string{"create_order", "list_orders"}, view.ToolNames())
}

func TestDeriveMCPToolView_AllowTrueEnablesExplicitAllowMode(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:    &openapi3.Operation{OperationID: "list_orders", Summary: "list orders"},
			Post:   &openapi3.Operation{OperationID: "create_order", Summary: "create order"},
			Delete: &openapi3.Operation{OperationID: "delete_order", Summary: "delete order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{Source: TykMCPServerSource{OperationID: "list_orders"}, Allow: boolPtr(false)},
			{Source: TykMCPServerSource{OperationID: "create_order"}, Allow: boolPtr(true)},
			{Source: TykMCPServerSource{OperationID: "delete_order"}},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 1)
	assert.Equal(t, []string{"create_order"}, view.ToolNames())
}

func TestDeriveMCPToolView_AllowFalseOnlyDoesNotRestrictExposure(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:    &openapi3.Operation{OperationID: "list_orders", Summary: "list orders"},
			Post:   &openapi3.Operation{OperationID: "create_order", Summary: "create order"},
			Delete: &openapi3.Operation{OperationID: "delete_order", Summary: "delete order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{Source: TykMCPServerSource{OperationID: "list_orders"}, Allow: boolPtr(false)},
			{Source: TykMCPServerSource{OperationID: "delete_order"}, Allow: boolPtr(false)},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, []string{"create_order", "delete_order", "list_orders"}, view.ToolNames())
}

func TestDeriveMCPToolView_PathMethodSourceForOperationWithoutOperationID(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				Summary: "list orders",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{
						Name:   "status",
						In:     openapi3.ParameterInQuery,
						Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
					}},
				},
			},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{
				Source: TykMCPServerSource{
					Path:   "/orders",
					Method: "GET",
				},
				Name:        "list_orders",
				Allow:       boolPtr(true),
				Description: "List orders without operationId",
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Equal(t, warningMissingOperationID, warnings[0].Reason)
	require.Len(t, view.Tools, 1)

	tool := view.Tools[0]
	assert.Empty(t, tool.OperationID)
	assert.Equal(t, "http:GET /orders", tool.SourceKey)
	assert.Equal(t, "list_orders", tool.Name)
	assert.Equal(t, "List orders without operationId", tool.Description)
	assert.Equal(t, http.MethodGet, tool.Method)
	assert.Equal(t, "/orders", tool.PathTemplate)
	assert.Equal(t, map[string]string{"status": DerivedParamLocationQuery}, tool.ParamLocations)
}

func TestDeriveMCPToolView_DefaultsToAllCanonicalTools(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:  &openapi3.Operation{OperationID: "list_orders"},
			Post: &openapi3.Operation{OperationID: "create_order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, nil)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 2)
	assert.Equal(t, []string{"create_order", "list_orders"}, view.ToolNames())
}

func TestDeriveMCPToolView_ValidationFailures(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "list_orders",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{
						Name:   "status",
						In:     openapi3.ParameterInQuery,
						Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
					}},
				},
			},
			Post: &openapi3.Operation{OperationID: "create_order"},
		}),
	))

	cases := []struct {
		name string
		cfg  *TykMCPServer
		want string
	}{
		{
			name: "unknown operationId source",
			cfg:  &TykMCPServer{Primitives: []TykMCPServerPrimitive{{Source: TykMCPServerSource{OperationID: "missing_order"}, Name: "missing", Allow: boolPtr(true)}}},
			want: "missing_order",
		},
		{
			name: "duplicate exposed names",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Allow: boolPtr(true)},
				{Source: TykMCPServerSource{OperationID: "create_order"}, Name: "orders", Allow: boolPtr(true)},
			}},
			want: "duplicate exposed tool name",
		},
		{
			name: "unknown parameter override",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "list_orders"}, Parameters: []TykMCPServerParameter{{Param: "customer_id", Description: "customer"}}},
			}},
			want: "customer_id",
		},
		{
			name: "source requires one selector",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "list_orders", Path: "/orders", Method: "GET"}, Name: "orders", Allow: boolPtr(true)},
			}},
			want: "exactly one source selector",
		},
		{
			name: "path method fallback rejected when operationId exists",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{Path: "/orders", Method: "GET"}, Name: "orders", Allow: boolPtr(true)},
			}},
			want: "has operationId",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := DeriveMCPToolView(src, tc.cfg)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
