package oas

import (
	"encoding/json"
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
		assert.Equal(t, "application/json", tools[0].RequestBodyContentType)
	}
}

func TestDeriveSourceTools_PreservesSelectedJSONRequestBodyMediaType(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "create_order",
				RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						"application/vnd.api+json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{Value: openapi3.NewObjectSchema().WithProperty("data", openapi3.NewStringSchema())},
						},
					},
				}},
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	assert.Equal(t, "application/vnd.api+json", tools[0].RequestBodyContentType)
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

func TestDeriveSourceTools_DerivesDefaultAnnotationsFromMethod(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "list_orders",
				Summary:     "List orders",
			},
			Put: &openapi3.Operation{
				OperationID: "replace_order",
			},
			Post: &openapi3.Operation{
				OperationID: "create_order",
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 3)

	byName := map[string]DerivedTool{}
	for _, tool := range tools {
		byName[tool.Name] = tool
	}

	assertDerivedToolAnnotations(t, byName["list_orders"].Annotations, "List orders", true, false, true, false)
	assertDerivedToolAnnotations(t, byName["replace_order"].Annotations, "replace_order", false, true, true, true)
	assertDerivedToolAnnotations(t, byName["create_order"].Annotations, "create_order", false, true, false, true)

	encoded, err := json.Marshal(byName["list_orders"])
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"destructiveHint":false`)
}

func TestDeriveSourceTools_DerivesOutputSchemaFromJSONResponses(t *testing.T) {
	t.Parallel()

	responseSchema := openapi3.NewObjectSchema()
	responseSchema.Description = "Order response"
	responseSchema.Required = []string{"id"}
	responseSchema.Properties = openapi3.Schemas{
		"id": &openapi3.SchemaRef{Value: &openapi3.Schema{
			Type:   &openapi3.Types{schemaTypeString},
			Format: "uuid",
		}},
		"status": &openapi3.SchemaRef{Value: &openapi3.Schema{
			Type: &openapi3.Types{schemaTypeString},
			Enum: []any{"new", "paid"},
		}},
		"items": &openapi3.SchemaRef{Value: &openapi3.Schema{
			Type: &openapi3.Types{schemaTypeArray},
			Items: &openapi3.SchemaRef{Value: &openapi3.Schema{
				Type: &openapi3.Types{schemaTypeString},
			}},
		}},
	}

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "get_order",
				Responses: deriveTestResponses(map[string]openapi3.Content{
					"201": {
						"application/json": deriveTestMedia(openapi3.NewStringSchema()),
					},
					"200": {
						"application/vnd.tyk+json": deriveTestMedia(openapi3.NewObjectSchema().WithProperty("vendor", openapi3.NewStringSchema())),
						"application/json":         deriveTestMedia(responseSchema),
					},
				}),
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	assert.Equal(t, map[string]any{
		"type":        "object",
		"description": "Order response",
		"properties": map[string]any{
			"id": map[string]any{
				"type":   "string",
				"format": "uuid",
			},
			"items": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "string",
				},
			},
			"status": map[string]any{
				"type": "string",
				"enum": []any{"new", "paid"},
			},
		},
		"required": []string{"id"},
	}, tools[0].OutputSchema)
}

func TestDeriveSourceTools_OutputSchemaSelectionAndWrapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		responses *openapi3.Responses
		want      map[string]any
	}{
		{
			name: "falls back to lowest JSON 2xx response",
			responses: deriveTestResponses(map[string]openapi3.Content{
				"202": {
					"application/json": deriveTestMedia(openapi3.NewObjectSchema().WithProperty("accepted", openapi3.NewBoolSchema())),
				},
				"201": {
					"application/vnd.tyk+json": deriveTestMedia(openapi3.NewObjectSchema().WithProperty("created", openapi3.NewStringSchema())),
				},
			}),
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"created": map[string]any{"type": "string"},
				},
			},
		},
		{
			name: "wraps array response schema under result",
			responses: deriveTestResponses(map[string]openapi3.Content{
				"200": {
					"application/json": deriveTestMedia(openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())),
				},
			}),
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"result": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "string",
						},
					},
				},
				"required": []string{"result"},
			},
		},
		{
			name: "omits non JSON response schema",
			responses: deriveTestResponses(map[string]openapi3.Content{
				"200": {
					"text/plain": deriveTestMedia(openapi3.NewStringSchema()),
				},
			}),
		},
		{
			name: "omits 204 response",
			responses: deriveTestResponses(map[string]openapi3.Content{
				"204": {
					"application/json": deriveTestMedia(openapi3.NewObjectSchema()),
				},
			}),
		},
		{
			name: "omits schema-less JSON response",
			responses: deriveTestResponses(map[string]openapi3.Content{
				"200": {
					"application/json": &openapi3.MediaType{},
				},
			}),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := newDeriveTestOAS(openapi3.NewPaths(
				openapi3.WithPath("/orders", &openapi3.PathItem{
					Get: &openapi3.Operation{
						OperationID: "list_orders",
						Responses:   tc.responses,
					},
				}),
			))

			tools, _, err := DeriveSourceTools(src, nil)
			require.NoError(t, err)
			require.Len(t, tools, 1)
			assert.Equal(t, tc.want, tools[0].OutputSchema)
		})
	}
}

func TestDeriveSourceTools_DerivesWholeBodyRequestSchema(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		schema *openapi3.Schema
		want   string
	}{
		{name: "object", schema: openapi3.NewObjectSchema(), want: schemaTypeObject},
		{name: "array", schema: openapi3.NewArraySchema(), want: schemaTypeArray},
		{name: "string", schema: openapi3.NewStringSchema(), want: schemaTypeString},
		{name: "integer", schema: openapi3.NewIntegerSchema(), want: schemaTypeInteger},
		{name: "number", schema: openapi3.NewFloat64Schema(), want: schemaTypeNumber},
		{name: "boolean", schema: openapi3.NewBoolSchema(), want: schemaTypeBoolean},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := newDeriveTestOAS(openapi3.NewPaths(
				openapi3.WithPath("/echo", &openapi3.PathItem{
					Post: &openapi3.Operation{
						OperationID: "echo_" + tc.name,
						RequestBody: &openapi3.RequestBodyRef{Value: &openapi3.RequestBody{
							Required: true,
							Content: openapi3.Content{
								"application/json": &openapi3.MediaType{
									Schema: &openapi3.SchemaRef{Value: tc.schema},
								},
							},
						}},
					},
				}),
			))

			tools, _, err := DeriveSourceTools(src, nil)
			require.NoError(t, err)
			require.Len(t, tools, 1)

			assert.Equal(t, map[string]string{"body": DerivedParamLocationBody}, tools[0].ParamLocations)
			assert.Equal(t, []string{"body"}, tools[0].ParamOrder)
			props := tools[0].InputSchema["properties"].(map[string]any)
			body := props["body"].(map[string]any)
			assert.Equal(t, tc.want, body["type"])
			assert.Equal(t, []string{"body"}, tools[0].InputSchema["required"])
		})
	}
}

func TestDeriveSourceTools_PreservesParameterOrderMetadata(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "path_id", In: openapi3.ParameterInPath, Required: true, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
				&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "z_last", In: openapi3.ParameterInQuery, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
			},
			Get: &openapi3.Operation{
				OperationID: "list_orders",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "a_first", In: openapi3.ParameterInQuery, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "middle", In: openapi3.ParameterInQuery, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
				},
			},
		}),
	))

	tools, _, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	assert.Equal(t, []string{"path_id", "z_last", "a_first", "middle"}, tools[0].ParamOrder)
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
		{name: "too long", operationID: strings.Repeat("a", maxMCPToolNameLength+1), want: "128"},
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

func TestValidateMCPToolName_UsesMCPSpecLengthLimit(t *testing.T) {
	t.Parallel()

	assert.NoError(t, ValidateMCPToolName(strings.Repeat("a", maxMCPToolNameLength)))

	err := ValidateMCPToolName(strings.Repeat("a", maxMCPToolNameLength+1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "128")
}

func TestSanitizeToolName_CollapsesUnderscoreRuns(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "create_order-v1.ok", SanitizeToolName("__create / order-v1.ok__"))
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

func assertDerivedToolAnnotations(
	t *testing.T,
	got *DerivedToolAnnotations,
	title string,
	readOnlyHint bool,
	destructiveHint bool,
	idempotentHint bool,
	openWorldHint bool,
) {

	t.Helper()

	require.NotNil(t, got)
	assert.Equal(t, title, got.Title)
	require.NotNil(t, got.ReadOnlyHint)
	assert.Equal(t, readOnlyHint, *got.ReadOnlyHint)
	require.NotNil(t, got.DestructiveHint)
	assert.Equal(t, destructiveHint, *got.DestructiveHint)
	require.NotNil(t, got.IdempotentHint)
	assert.Equal(t, idempotentHint, *got.IdempotentHint)
	require.NotNil(t, got.OpenWorldHint)
	assert.Equal(t, openWorldHint, *got.OpenWorldHint)
}

func deriveTestResponses(contentByStatus map[string]openapi3.Content) *openapi3.Responses {
	responses := openapi3.NewResponses()
	for status, content := range contentByStatus {
		responses.Set(status, &openapi3.ResponseRef{Value: &openapi3.Response{Content: content}})
	}
	return responses
}

func deriveTestMedia(schema *openapi3.Schema) *openapi3.MediaType {
	return &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: schema}}
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

func TestDeriveSourceTools_RejectsDuplicateExposedParameterNames(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "get_order",
				Parameters: openapi3.Parameters{
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "x", In: openapi3.ParameterInQuery, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "x", In: openapi3.ParameterInHeader, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
					&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "header_x", In: openapi3.ParameterInHeader, Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}}},
				},
			},
		}),
	))

	_, _, err := DeriveSourceTools(src, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `operationId "get_order"`)
	assert.Contains(t, err.Error(), `duplicate exposed parameter name "header_x"`)
}
