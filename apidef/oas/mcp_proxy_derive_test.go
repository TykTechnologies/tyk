package oas

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDeriveTestOAS(paths *openapi3.Paths) *OAS {
	return &OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "orders", Version: "1.0.0"},
			Paths:   paths,
		},
	}
}

func TestAdapterLoopURLUsesMCPPath(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "tyk://rest-1/mcp", AdapterLoopURL("rest-1"))
}

func TestAdapterLoopURLForSourceFallsBackWhenSourceHasMCPPath(t *testing.T) {
	t.Parallel()

	regular := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "list_orders"}}),
	))
	withMCPPath := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/mcp", &openapi3.PathItem{Post: &openapi3.Operation{OperationID: "mcp_endpoint"}}),
	))

	assert.Equal(t, "tyk://rest-1/mcp", AdapterLoopURLForSource("rest-1", regular))
	assert.Equal(t, "tyk://rest-1__mcp-server", AdapterLoopURLForSource("rest-1", withMCPPath))
}

func TestDeriveSourcePrimitives_SkipsMissingOperationIDAndEmitsToolPrimitive(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:  &openapi3.Operation{Summary: "missing operation id"},
			Post: &openapi3.Operation{OperationID: "create_order", Summary: "create order"},
		}),
	))

	primitives, warnings, err := DeriveSourcePrimitives(src)
	require.NoError(t, err)
	require.Len(t, primitives, 1)
	assert.Equal(t, MCPPrimitiveTypeTool, primitives[0].Type)
	assert.Equal(t, "create_order", primitives[0].Tool.Name)

	require.Len(t, warnings, 1)
	assert.Equal(t, "GET /orders", warnings[0].Operation)
	assert.Equal(t, "GET", warnings[0].Method)
	assert.Equal(t, "/orders", warnings[0].Path)
	assert.Equal(t, "missing operationId", warnings[0].Reason)
}

func TestDeriveSourceTools_RespectsEndpointVisibility(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/allowed", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "allowed_op"}}),
		openapi3.WithPath("/blocked", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "blocked_op"}}),
		openapi3.WithPath("/internal", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "internal_op"}}),
		openapi3.WithPath("/not-allowed", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "not_allowed_op"}}),
	))
	src.SetTykExtension(&XTykAPIGateway{
		Middleware: &Middleware{
			Operations: Operations{
				"allowed_op":     {Allow: &Allowance{Enabled: true}},
				"blocked_op":     {Block: &Allowance{Enabled: true}},
				"internal_op":    {Internal: &Internal{Enabled: true}},
				"not_allowed_op": {},
			},
		},
	})

	tools, warnings, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "allowed_op", tools[0].Name)

	reasons := map[string]string{}
	for _, warning := range warnings {
		reasons[warning.Operation] = warning.Reason
	}
	assert.Equal(t, "operation marked blocked - skipped", reasons["blocked_op"])
	assert.Equal(t, "operation marked internal - skipped", reasons["internal_op"])
	assert.Equal(t, "operation not in source allow-list - skipped", reasons["not_allowed_op"])
}

func TestDeriveSourceTools_DoesNotSynthesizeFallbackNames(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
			Get: &openapi3.Operation{},
		}),
	))

	tools, warnings, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	assert.Empty(t, tools)
	require.Len(t, warnings, 1)
	assert.Equal(t, "missing operationId", warnings[0].Reason)
}

func TestDeriveSourceTools_PrefersExactJSONRequestBodyMediaType(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "create_order",
				RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						"application/vnd.api+json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{Value: openapi3.NewObjectSchema().WithProperty("vendor", openapi3.NewStringSchema())},
						},
						"application/json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{Value: openapi3.NewObjectSchema().WithProperty("exact", openapi3.NewStringSchema())},
						},
					},
				}},
			},
		}),
	))

	for i := 0; i < 64; i++ {
		tools, _, err := DeriveSourceTools(src, nil)
		require.NoError(t, err)
		require.Len(t, tools, 1)

		props := tools[0].InputSchema["properties"].(map[string]any)
		assert.Contains(t, props, "exact")
		assert.NotContains(t, props, "vendor")
	}
}

func TestDeriveSourceTools_DerivesFormURLEncodedRequestBody(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "submit_order",
				RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/x-www-form-urlencoded": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
								Type:     &openapi3.Types{schemaTypeObject},
								Required: []string{"sku"},
								Properties: openapi3.Schemas{
									"sku": &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
									"qty": &openapi3.SchemaRef{Value: openapi3.NewIntegerSchema()},
								},
							}},
						},
					},
				}},
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	assert.Equal(t, "application/x-www-form-urlencoded", tools[0].RequestBodyContentType)
	assert.Equal(t, map[string]string{
		"qty": DerivedParamLocationBodyPrefix + "qty",
		"sku": DerivedParamLocationBodyPrefix + "sku",
	}, tools[0].ParamLocations)
	assert.Equal(t, []string{"sku"}, tools[0].InputSchema["required"])
}

func TestDeriveSourceTools_AllowsMCPCompatibleOperationIDNames(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/camel", &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: "createOrder"},
		}),
		openapi3.WithPath("/hyphen", &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: "create-order"},
		}),
		openapi3.WithPath("/dot", &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: "create.order"},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)

	require.NoError(t, err)
	assert.Equal(t, []string{"create-order", "create.order", "createOrder"}, toolNames(tools))
}

func TestDeriveSourceTools_RejectsInvalidExposedToolNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		operationID string
		want        string
	}{
		{name: "space", operationID: "create order", want: "invalid tool name"},
		{name: "slash", operationID: "create/order", want: "invalid tool name"},
		{name: "too long", operationID: strings.Repeat("a", 65), want: "64"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := newDeriveTestOAS(openapi3.NewPaths(
				openapi3.WithPath("/orders", &openapi3.PathItem{
					Get: &openapi3.Operation{OperationID: tc.operationID},
				}),
			))

			_, _, err := DeriveSourceTools(src, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestDeriveSourceTools_RejectsDuplicateToolNames(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "same_name"}}),
		openapi3.WithPath("/customers", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "same_name"}}),
	))

	_, _, err := DeriveSourceTools(src, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate tool name")
}

func toolNames(tools []DerivedTool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestDeriveSourceTools_PrefixesParameterNameCollisions(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "get_order",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "id", In: openapi3.ParameterInPath, Required: true, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "id", In: openapi3.ParameterInQuery, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "id", In: openapi3.ParameterInHeader, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
				},
				RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{Value: openapi3.NewObjectSchema().WithProperty("id", openapi3.NewStringSchema())},
						},
					},
				}},
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	assert.Equal(t, map[string]string{
		"path_id":   DerivedParamLocationPath,
		"query_id":  DerivedParamLocationQuery,
		"header_id": DerivedParamLocationHeader,
		"id":        DerivedParamLocationBodyPrefix + "id",
	}, tools[0].ParamLocations)
	assert.Equal(t, map[string]string{
		"path_id":   "id",
		"query_id":  "id",
		"header_id": "id",
		"id":        "id",
	}, tools[0].ParamSourceNames)
	props := tools[0].InputSchema["properties"].(map[string]any)
	assert.Contains(t, props, "path_id")
	assert.Contains(t, props, "query_id")
	assert.Contains(t, props, "header_id")
	assert.Contains(t, props, "id")
}
