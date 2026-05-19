package oas

import (
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

func TestDeriveSourcePrimitives_SkipsMissingOperationIDAndEmitsToolPrimitive(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/orders", &openapi3.PathItem{
			Get:  &openapi3.Operation{Summary: "missing operation id"},
			Post: &openapi3.Operation{OperationID: "createOrder", Summary: "create order"},
		}),
	))

	primitives, warnings, err := DeriveSourcePrimitives(src)
	require.NoError(t, err)
	require.Len(t, primitives, 1)
	assert.Equal(t, MCPPrimitiveTypeTool, primitives[0].Type)
	assert.Equal(t, "createOrder", primitives[0].Tool.Name)

	require.Len(t, warnings, 1)
	assert.Equal(t, "GET /orders", warnings[0].Operation)
	assert.Equal(t, "GET", warnings[0].Method)
	assert.Equal(t, "/orders", warnings[0].Path)
	assert.Equal(t, "missing operationId", warnings[0].Reason)
}

func TestDeriveSourceTools_RespectsEndpointVisibility(t *testing.T) {
	t.Parallel()

	src := newDeriveTestOAS(openapi3.NewPaths(
		openapi3.WithPath("/allowed", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "allowedOp"}}),
		openapi3.WithPath("/blocked", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "blockedOp"}}),
		openapi3.WithPath("/internal", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "internalOp"}}),
		openapi3.WithPath("/not-allowed", &openapi3.PathItem{Get: &openapi3.Operation{OperationID: "notAllowedOp"}}),
	))
	src.SetTykExtension(&XTykAPIGateway{
		Middleware: &Middleware{
			Operations: Operations{
				"allowedOp":    {Allow: &Allowance{Enabled: true}},
				"blockedOp":    {Block: &Allowance{Enabled: true}},
				"internalOp":   {Internal: &Internal{Enabled: true}},
				"notAllowedOp": {},
			},
		},
	})

	tools, warnings, err := DeriveSourceTools(src, nil)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "allowedOp", tools[0].Name)

	reasons := map[string]string{}
	for _, warning := range warnings {
		reasons[warning.Operation] = warning.Reason
	}
	assert.Equal(t, "operation marked blocked - skipped", reasons["blockedOp"])
	assert.Equal(t, "operation marked internal - skipped", reasons["internalOp"])
	assert.Equal(t, "operation not in source allow-list - skipped", reasons["notAllowedOp"])
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
				OperationID: "createOrder",
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
