package gateway

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func TestExtractOASPathParamSchemas(t *testing.T) {
	t.Run("operation params override path-item params", func(t *testing.T) {
		pathItem := &openapi3.PathItem{
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
			},
		}
		operation := &openapi3.Operation{
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"integer"},
						Pattern: "[0-9]+",
					}},
				}},
			},
		}

		result := extractOASPathParamSchemas(pathItem, operation)
		assert.Equal(t, map[string]httputil.ParamSchema{
			"id": {Type: "integer", Pattern: "[0-9]+"},
		}, result)
	})

	t.Run("path-item params used when no operation params", func(t *testing.T) {
		pathItem := &openapi3.PathItem{
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z]$",
					}},
				}},
			},
		}

		result := extractOASPathParamSchemas(pathItem, nil)
		assert.Equal(t, map[string]httputil.ParamSchema{
			"id": {Type: "string", Pattern: "^[a-z]$"},
		}, result)
	})

	t.Run("non-path params are ignored", func(t *testing.T) {
		pathItem := &openapi3.PathItem{
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "X-Header", In: "header",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
			},
		}

		result := extractOASPathParamSchemas(pathItem, nil)
		assert.Nil(t, result)
	})

	t.Run("returns nil when no path params", func(t *testing.T) {
		pathItem := &openapi3.PathItem{}
		result := extractOASPathParamSchemas(pathItem, &openapi3.Operation{})
		assert.Nil(t, result)
	})

	t.Run("multiple path params collected", func(t *testing.T) {
		pathItem := &openapi3.PathItem{}
		operation := &openapi3.Operation{
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "deptId", In: "path",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"integer"},
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "empId", In: "path",
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z]+$",
					}},
				}},
			},
		}

		result := extractOASPathParamSchemas(pathItem, operation)
		assert.Equal(t, map[string]httputil.ParamSchema{
			"deptId": {Type: "integer"},
			"empId":  {Type: "string", Pattern: "^[a-z]+$"},
		}, result)
	})
}

func TestCollectPathParams(t *testing.T) {
	t.Run("nil ref is skipped", func(t *testing.T) {
		dst := make(map[string]httputil.ParamSchema)
		params := openapi3.Parameters{nil}
		collectPathParams(params, dst)
		assert.Empty(t, dst)
	})

	t.Run("nil value is skipped", func(t *testing.T) {
		dst := make(map[string]httputil.ParamSchema)
		params := openapi3.Parameters{&openapi3.ParameterRef{Value: nil}}
		collectPathParams(params, dst)
		assert.Empty(t, dst)
	})

	t.Run("param without schema gets empty ParamSchema", func(t *testing.T) {
		dst := make(map[string]httputil.ParamSchema)
		params := openapi3.Parameters{
			{Value: &openapi3.Parameter{Name: "id", In: "path"}},
		}
		collectPathParams(params, dst)
		assert.Equal(t, httputil.ParamSchema{}, dst["id"])
	})
}
