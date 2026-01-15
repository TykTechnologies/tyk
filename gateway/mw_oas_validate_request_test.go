package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
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
          },
          "createdAt": {
            "type": "string",
            "format": "date-time"
          },
          "expiryOn": {
            "type": "string",
            "format": "date"
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
        "parameters": [{
          "name": "id",
          "in": "query",
          "required": false,
          "schema": {
            "type": "integer"
          },
          "description": "description"
        }],
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
    },
    "/test": {
      "get": {
        "operationId": "testget",
        "parameters": [
          {
            "in": "header",
            "name": "test",
            "required": true,
            "schema": {
              "items": {
                "maxLength": 5,
                "minLength": 1,
                "pattern": "^[A-Za-z]+$",
                "type": "string"
              },
              "maxItems": 999,
              "minItems": 1,
              "type": "array"
            }
          }
        ],
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
	const getOperationID = "testget"

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
				getOperationID: {
					ValidateRequest: &oas.ValidateRequest{
						Enabled:           true,
						ErrorResponseCode: http.StatusUnprocessableEntity,
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

	apis := ts.Gw.BuildAndLoadAPI(
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
		},
	)

	headers := map[string]string{}

	t.Run("default error response code", func(t *testing.T) {
		check := func(t *testing.T) {
			t.Helper()
			_, _ = ts.Run(t, []test.TestCase{
				{Data: `{"name": 123}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product/push"},
				{Data: `{"name": 123}`, Code: http.StatusUnprocessableEntity, Method: http.MethodPost, Headers: headers, Path: "/product/post"},
				{Data: `{"name": "my-product"}`, Code: http.StatusOK, Method: http.MethodPost, Headers: headers, Path: "/product/post"},
				{Data: `{"name": "my-product", "owner": {"name": 123}}`, Code: http.StatusUnprocessableEntity, Method: http.MethodPost,
					BodyNotMatch: `Schema:`, Headers: headers, Path: "/product/post"},
				{Data: `{"name": "my-product", "owner": {"name": "Furkan"}}`, Code: http.StatusUnprocessableEntity, BodyMatch: "query has an error", Method: http.MethodPost,
					Headers: headers, Path: "/product/post?id=ten"},
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
		}

		t.Run("stripListenPath=false", func(t *testing.T) {
			check(t)
		})

		t.Run("stripListenPath=true", func(t *testing.T) {
			apis[0].Proxy.StripListenPath = true
			apis[1].Proxy.StripListenPath = true
			apis[2].Proxy.StripListenPath = true
			ts.Gw.LoadAPI(apis...)
			check(t)
		})

		t.Run("validate date/date-time format", func(t *testing.T) {
			apiPath := "/product/post"
			_, _ = ts.Run(t, []test.TestCase{
				{Data: `{"name": "123", "createdAt": "2016-02-30T14:30:15Z"}`, Code: http.StatusUnprocessableEntity,
					Method: http.MethodPost, Headers: headers, Path: apiPath},
				{Data: `{"name": "123", "createdAt": "2016-02-28T30:30:15Z"}`, Code: http.StatusUnprocessableEntity,
					Method: http.MethodPost, Headers: headers, Path: apiPath},
				{Data: `{"name": "123", "createdAt": "2016-02-28T12:30:15Z"}`, Code: http.StatusOK,
					Method: http.MethodPost, Headers: headers, Path: apiPath},
				{Data: `{"name": "123", "expiryOn": "2016-02-28"}`, Code: http.StatusOK,
					Method: http.MethodPost, Headers: headers, Path: apiPath},
			}...)
		})
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

	t.Run("multiple headers with the same name", func(t *testing.T) {
		headerName := "test"

		validHeader := map[string][]string{headerName: {"y", "x"}}
		invalidHeader1 := map[string][]string{headerName: {"y", "toolong"}}
		invalidHeader2 := map[string][]string{headerName: {"toolong", "x"}}

		path := "/product/test"
		_, _ = ts.Run(t, []test.TestCase{
			{Code: http.StatusOK, Method: http.MethodGet, HeadersArray: validHeader, Path: path},
			{Code: http.StatusUnprocessableEntity, Method: http.MethodGet, HeadersArray: invalidHeader1, Path: path},
			{Code: http.StatusUnprocessableEntity, Method: http.MethodGet, HeadersArray: invalidHeader2, Path: path},
		}...)
	})
}

func TestValidateRequest_AfterMigration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/listen/"
		spec.Proxy.StripListenPath = true
		spec.ConfigDataDisabled = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.ValidateJSON = []apidef.ValidatePathMeta{
				{
					Method: http.MethodPost,
					Path:   "/post",
					Schema: map[string]interface{}{
						"required": []string{"name"},
					},
					ErrorResponseCode: http.StatusTeapot,
				},
			}
		})
	})[0]

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/listen/without_validation", Data: "{not_valid}", Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/listen/post", Data: `{"age":27}`, Code: http.StatusTeapot},
		{Method: http.MethodPost, Path: "/listen/post", Data: `{"name":"Furkan"}`, Code: http.StatusOK},
	}...)

	migratedAPI, _, err := oas.MigrateAndFillOAS(api.APIDefinition)
	assert.NoError(t, err)

	ts.Gw.LoadAPI(&APISpec{APIDefinition: migratedAPI.Classic, OAS: *migratedAPI.OAS})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/listen/without_validation", Data: "{not_valid}", Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/listen/post", Data: `{"age":27}`, Code: http.StatusTeapot},
		{Method: http.MethodPost, Path: "/listen/post", Data: `{"name":"Furkan"}`, Code: http.StatusOK},
	}...)
}

func TestValidateRequest_NormalizeHeaders(t *testing.T) {
	customHeader := "X-Custom"
	tests := []struct {
		name     string
		input    http.Header
		expected http.Header
	}{
		{
			name: "Single value headers remain unchanged",
			input: http.Header{
				header.Accept:      []string{"application/json"},
				header.ContentType: []string{"application/json"},
				header.UserAgent:   []string{"Tyk-Test"},
			},
			expected: http.Header{
				header.Accept:      []string{"application/json"},
				header.ContentType: []string{"application/json"},
				header.UserAgent:   []string{"Tyk-Test"},
			},
		},
		{
			name: "Multiple value headers are joined with commas",
			input: http.Header{
				header.Accept:    []string{"application/json", "text/html"},
				customHeader:     []string{"value1", "value2", "value3"},
				header.UserAgent: []string{"Tyk-Test"},
			},
			expected: http.Header{
				header.Accept:    []string{"application/json,text/html"},
				customHeader:     []string{"value1,value2,value3"},
				header.UserAgent: []string{"Tyk-Test"},
			},
		},
		{
			name: "Excluded headers remain unchanged even with multiple values",
			input: http.Header{
				header.SetCookie:        []string{"cookie1=value1", "cookie2=value2"},
				header.ContentLength:    []string{"100", "200"},
				header.TransferEncoding: []string{"chunked", "gzip"},
				header.Host:             []string{"example.com", "test.com"},
			},
			expected: http.Header{
				header.SetCookie:        []string{"cookie1=value1", "cookie2=value2"},
				header.ContentLength:    []string{"100", "200"},
				header.TransferEncoding: []string{"chunked", "gzip"},
				header.Host:             []string{"example.com", "test.com"},
			},
		},
		{
			name: "Mixed regular and excluded headers",
			input: http.Header{
				header.Accept:           []string{"application/json", "text/html"},
				header.SetCookie:        []string{"cookie1=value1", "cookie2=value2"},
				header.Cookie:           []string{"cookie1=value1", "cookie2=value2"},
				customHeader:            []string{"value1", "value2", "value3"},
				header.ContentLength:    []string{"100"},
				header.TransferEncoding: []string{"chunked"},
				header.Host:             []string{"example.com"},
			},
			expected: http.Header{
				header.Accept:           []string{"application/json,text/html"},
				header.SetCookie:        []string{"cookie1=value1", "cookie2=value2"},
				header.Cookie:           []string{"cookie1=value1; cookie2=value2"},
				customHeader:            []string{"value1,value2,value3"},
				header.ContentLength:    []string{"100"},
				header.TransferEncoding: []string{"chunked"},
				header.Host:             []string{"example.com"},
			},
		},
		{
			name:     "Empty headers remain empty",
			input:    http.Header{},
			expected: http.Header{},
		},
		{
			name: "Headers with empty values",
			input: http.Header{
				"X-Empty":  []string{""},
				"X-Empty2": []string{"", ""},
			},
			expected: http.Header{
				"X-Empty":  []string{""},
				"X-Empty2": []string{","},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizeHeaders(tt.input)

			assert.Equal(t, tt.expected, tt.input)
		})
	}
}
