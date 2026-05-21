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
				"source":{"operationId":"createOrder"},
				"name":"create_order",
				"allow":true,
				"description":"Place a new order for a customer",
				"parameters":[{
					"param":"customer_id",
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
	assert.Equal(t, "createOrder", ext.Primitives[0].Source.OperationID)
	assert.Equal(t, "create_order", ext.Primitives[0].Name)
	require.NotNil(t, ext.Primitives[0].Allow)
	assert.True(t, *ext.Primitives[0].Allow)
	require.Len(t, ext.Primitives[0].Parameters, 1)
	assert.Equal(t, "customer_id", ext.Primitives[0].Parameters[0].Param)

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
				OperationID: "listOrders",
				Summary:     "list orders",
			},
			Post: &openapi3.Operation{
				OperationID: "createOrder",
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
				Source:      TykMCPServerSource{OperationID: "createOrder"},
				Name:        "create_order",
				Allow:       boolPtr(true),
				Description: "Place a new order for a customer",
				Parameters: []TykMCPServerParameter{
					{
						Param:       "customer_id",
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
	assert.Equal(t, "createOrder", tool.OperationID)
	assert.Equal(t, "createOrder", tool.CanonicalName)
	assert.Equal(t, "create_order", tool.Name)
	assert.Equal(t, "Place a new order for a customer", tool.Description)
	assert.Equal(t, map[string]string{"customer_id": DerivedParamLocationQuery}, tool.ParamLocations)

	props := tool.InputSchema["properties"].(map[string]any)
	customer := props["customer_id"].(map[string]any)
	assert.Equal(t, "Unique identifier of the customer placing the order", customer["description"])
}

func TestDeriveMCPToolView_PrimitivesWithoutAllowDoNotRestrictExposure(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:  &openapi3.Operation{OperationID: "listOrders", Summary: "list orders"},
			Post: &openapi3.Operation{OperationID: "createOrder", Summary: "create order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{
				Source:      TykMCPServerSource{OperationID: "createOrder"},
				Name:        "create_order",
				Description: "Place a new order",
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 2)
	assert.Equal(t, []string{"create_order", "listOrders"}, view.ToolNames())
}

func TestDeriveMCPToolView_AnyAllowFieldEnablesExplicitAllowMode(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:    &openapi3.Operation{OperationID: "listOrders", Summary: "list orders"},
			Post:   &openapi3.Operation{OperationID: "createOrder", Summary: "create order"},
			Delete: &openapi3.Operation{OperationID: "deleteOrder", Summary: "delete order"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, &TykMCPServer{
		Primitives: []TykMCPServerPrimitive{
			{Source: TykMCPServerSource{OperationID: "listOrders"}, Allow: boolPtr(false)},
			{Source: TykMCPServerSource{OperationID: "createOrder"}, Allow: boolPtr(true)},
			{Source: TykMCPServerSource{OperationID: "deleteOrder"}},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 1)
	assert.Equal(t, []string{"createOrder"}, view.ToolNames())
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
			Get:  &openapi3.Operation{OperationID: "listOrders"},
			Post: &openapi3.Operation{OperationID: "createOrder"},
		}),
	))

	view, warnings, err := DeriveMCPToolView(src, nil)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, view.Tools, 2)
	assert.Equal(t, []string{"createOrder", "listOrders"}, view.ToolNames())
}

func TestDeriveMCPToolView_ValidationFailures(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "listOrders",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{
						Name:   "status",
						In:     openapi3.ParameterInQuery,
						Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
					}},
				},
			},
			Post: &openapi3.Operation{OperationID: "createOrder"},
		}),
	))

	cases := []struct {
		name string
		cfg  *TykMCPServer
		want string
	}{
		{
			name: "unknown operationId source",
			cfg:  &TykMCPServer{Primitives: []TykMCPServerPrimitive{{Source: TykMCPServerSource{OperationID: "missingOrder"}, Name: "missing", Allow: boolPtr(true)}}},
			want: "missingOrder",
		},
		{
			name: "duplicate exposed names",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "listOrders"}, Name: "orders", Allow: boolPtr(true)},
				{Source: TykMCPServerSource{OperationID: "createOrder"}, Name: "orders", Allow: boolPtr(true)},
			}},
			want: "duplicate exposed tool name",
		},
		{
			name: "unknown parameter override",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "listOrders"}, Parameters: []TykMCPServerParameter{{Param: "customer_id", Description: "customer"}}},
			}},
			want: "customer_id",
		},
		{
			name: "source requires one selector",
			cfg: &TykMCPServer{Primitives: []TykMCPServerPrimitive{
				{Source: TykMCPServerSource{OperationID: "listOrders", Path: "/orders", Method: "GET"}, Name: "orders", Allow: boolPtr(true)},
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
