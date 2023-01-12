package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

const testOASForValidateRequest = `{
  "openapi": "3.0.0",
  "components": {
    "schemas": {
      "Country": {
        "properties": {
          "name": {
            "type": "string"
          }
        }
      },
      "Owner": {
        "properties": {
          "name": {
            "type": "string"
          },
          "country": {
            "$ref": "#/components/schemas/Country"
          }
        }
      },
      "Product": {
        "properties": {
          "name": {
            "type": "string"
          },
          "owner": {
            "$ref": "#/components/schemas/Owner"
          }
        }
      }
    }
  },
  "info": {
    "title": "validate-request",
    "version": "1.0.0"
  },
  "paths": {
    "/post": {
      "post": {
        "operationId": "postpost",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/Product"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": ""
          }
        }
      }
    }
  },
  "servers": [
    {
      "url": "/"
    }
  ]
}`

func TestValidateRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const operationID = "postpost"

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(testOASForValidateRequest))
	assert.NoError(t, err)

	xTykAPIGateway := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				operationID: {
					ValidateRequest: &oas.ValidateRequest{
						Enabled: true,
					},
				},
			},
		},
	}

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(xTykAPIGateway)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)

	err = oasAPI.Validate(context.Background())
	assert.NoError(t, err)

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.VersionData = def.VersionData
			spec.Name = "without regexp"
			spec.OAS = oasAPI
			spec.IsOAS = true
			spec.Proxy.ListenPath = "/product"
		},
		func(spec *APISpec) {
			spec.VersionData = def.VersionData
			spec.OAS = oasAPI
			spec.IsOAS = true
			spec.Proxy.ListenPath = "/product-regexp1/{name:.*}"
			spec.UseKeylessAccess = true
		},
		func(spec *APISpec) {
			spec.VersionData = def.VersionData
			spec.OAS = oasAPI
			spec.IsOAS = true
			spec.Proxy.ListenPath = "/product-regexp2/{name:.*}/suffix"
			spec.UseKeylessAccess = true
		})

	headers := map[string]string{"Content-Type": "application/json"}

	t.Run("default error response code", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Data: `{"name": 123}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product/push"},
			{Data: `{"name": 123}`, Code: http.StatusUnprocessableEntity, Method: http.MethodPost, Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product"}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product", "owner": {"name": 123}}`, Code: http.StatusUnprocessableEntity, Method: http.MethodPost,
				Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan"}}`, Code: http.StatusOK, Method: http.MethodPost,
				Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": 123}}}`, Code: http.StatusUnprocessableEntity, Method: http.MethodPost,
				Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": "Türkiye"}}}`, Code: http.StatusOK, Method: http.MethodPost,
				Headers: headers, Path: "/product/post"},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": 123}}}`, Domain: "custom-domain",
				Code: http.StatusUnprocessableEntity, Method: http.MethodPost, Headers: headers, Path: "/product-regexp1/something/post", Client: test.NewClientLocal()},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": "Türkiye"}}}`, Domain: "custom-domain",
				Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product-regexp1/something/post", Client: test.NewClientLocal()},
			{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": "Türkiye"}}}`, Domain: "custom-domain",
				Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product-regexp2/something/suffix/post", Client: test.NewClientLocal()},
		}...)
	})

	t.Run("custom error response code", func(t *testing.T) {
		xTykAPIGateway.Middleware.Operations[operationID].ValidateRequest.ErrorResponseCode = http.StatusTeapot
		oasAPI.ExtractTo(&def)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.VersionData = def.VersionData
			spec.OAS = oasAPI
			spec.IsOAS = true
			spec.Proxy.ListenPath = "/product"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Data: `{"name": 123}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product/push"},
			{Data: `{"name": 123}`, Code: http.StatusTeapot, Method: http.MethodPost, Headers: headers, Path: "/product/post"},
		}...)
	})

}
