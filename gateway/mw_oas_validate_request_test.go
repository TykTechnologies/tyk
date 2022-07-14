package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
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

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(testOASForValidateRequest))
	assert.NoError(t, err)

	xTykAPIGateway := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"postpost": {
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

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.VersionData = def.VersionData
		spec.Name = "furkan"
		spec.OAS = oasAPI
		spec.IsOAS = true
		spec.Proxy.ListenPath = "/"
	})

	headers := map[string]string{"Content-Type": "application/json"}

	_, _ = ts.Run(t, []test.TestCase{
		{Data: `{"name": 123}`, Code: http.StatusBadRequest, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product"}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product", "owner": {"name": 123}}`, Code: http.StatusBadRequest, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product", "owner": {"name": "Furkan"}}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": 123}}}`, Code: http.StatusBadRequest, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": "Türkiye"}}}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/post"},
		{Data: `{"name": "my-product", "owner": {"name": "Furkan", "country": {"name": "Türkiye"}}}`, Domain: "custom-domain",
			Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/post", Client: test.NewClientLocal()},
	}...)
}
