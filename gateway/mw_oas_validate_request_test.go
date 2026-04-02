package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
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

// TestValidateRequest_PrefixMatching verifies that OAS validateRequest middleware
// respects gateway-level EnablePathPrefixMatching configuration.
// When prefix matching is enabled, a request to /anything/extra should be validated
// against the /anything operation.
func TestValidateRequest_PrefixMatching(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Enable prefix matching at gateway level
	conf := ts.Gw.GetConfig()
	conf.HttpServerOptions.EnablePathPrefixMatching = true
	conf.HttpServerOptions.EnablePathSuffixMatching = false
	ts.Gw.SetConfig(conf)

	// Create OAS spec with required header parameter on /anything
	const oasSpec = `{
		"openapi": "3.0.0",
		"info": {"title": "Prefix Match Test", "version": "1.0.0"},
		"paths": {
			"/anything": {
				"get": {
					"operationId": "getanything",
					"parameters": [{
						"name": "X-Required-Header",
						"in": "header",
						"required": true,
						"schema": {"type": "string"}
					}],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
	assert.NoError(t, err)

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getanything": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled:           true,
						ErrorResponseCode: http.StatusUnprocessableEntity,
					},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Prefix Match Validate Test"
		spec.APIID = "prefix-validate-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// Exact path match - should validate and fail (missing header)
		{
			Method:    http.MethodGet,
			Path:      "/api/anything",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Required-Header`,
		},
		// Exact path match - should validate and pass (header present)
		{
			Method:  http.MethodGet,
			Path:    "/api/anything",
			Headers: map[string]string{"X-Required-Header": "test"},
			Code:    http.StatusOK,
		},
		// Prefix match - request to /anything/extra should validate against /anything
		{
			Method:    http.MethodGet,
			Path:      "/api/anything/extra",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Required-Header`,
		},
		// Prefix match - should pass when header is provided
		{
			Method:  http.MethodGet,
			Path:    "/api/anything/extra",
			Headers: map[string]string{"X-Required-Header": "test"},
			Code:    http.StatusOK,
		},
		// Deeper prefix match
		{
			Method:    http.MethodGet,
			Path:      "/api/anything/extra/deep/path",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Required-Header`,
		},
	}...)
}

// TestValidateRequest_SuffixMatching verifies that OAS validateRequest middleware
// respects gateway-level EnablePathSuffixMatching configuration.
func TestValidateRequest_SuffixMatching(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Enable suffix matching at gateway level
	conf := ts.Gw.GetConfig()
	conf.HttpServerOptions.EnablePathPrefixMatching = false
	conf.HttpServerOptions.EnablePathSuffixMatching = true
	ts.Gw.SetConfig(conf)

	// Create OAS spec with required header parameter
	const oasSpec = `{
		"openapi": "3.0.0",
		"info": {"title": "Suffix Match Test", "version": "1.0.0"},
		"paths": {
			"/users": {
				"get": {
					"operationId": "getusers",
					"parameters": [{
						"name": "X-Auth",
						"in": "header",
						"required": true,
						"schema": {"type": "string"}
					}],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
	assert.NoError(t, err)

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getusers": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled:           true,
						ErrorResponseCode: http.StatusUnprocessableEntity,
					},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Suffix Match Validate Test"
		spec.APIID = "suffix-validate-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// Exact path match - should validate
		{
			Method:    http.MethodGet,
			Path:      "/api/users",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Auth`,
		},
		// Suffix match - /prefix/users should match /users
		{
			Method:    http.MethodGet,
			Path:      "/api/v1/users",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Auth`,
		},
		// Should pass with header
		{
			Method:  http.MethodGet,
			Path:    "/api/v1/users",
			Headers: map[string]string{"X-Auth": "token"},
			Code:    http.StatusOK,
		},
	}...)
}

// TestValidateRequest_BothMatchingEnabled verifies that when both prefix and suffix
// matching are enabled, the regex becomes ^/path$ (exact match).
func TestValidateRequest_BothMatchingEnabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Enable both prefix and suffix matching - this creates ^/path$ regex (exact match)
	conf := ts.Gw.GetConfig()
	conf.HttpServerOptions.EnablePathPrefixMatching = true
	conf.HttpServerOptions.EnablePathSuffixMatching = true
	ts.Gw.SetConfig(conf)

	const oasSpec = `{
		"openapi": "3.0.0",
		"info": {"title": "Exact Match Test", "version": "1.0.0"},
		"paths": {
			"/items": {
				"get": {
					"operationId": "getitems",
					"parameters": [{
						"name": "X-Token",
						"in": "header",
						"required": true,
						"schema": {"type": "string"}
					}],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
	assert.NoError(t, err)

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getitems": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled:           true,
						ErrorResponseCode: http.StatusUnprocessableEntity,
					},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Both Matching Validate Test"
		spec.APIID = "both-validate-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// Exact path match - should validate and fail
		{
			Method:    http.MethodGet,
			Path:      "/api/items",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Token`,
		},
		// Exact path match with header - should pass
		{
			Method:  http.MethodGet,
			Path:    "/api/items",
			Headers: map[string]string{"X-Token": "valid"},
			Code:    http.StatusOK,
		},
		// Non-exact path - should NOT validate (exact match with ^/items$)
		{
			Method: http.MethodGet,
			Path:   "/api/items/123",
			Code:   http.StatusOK,
		},
		// Non-exact path with prefix - should NOT validate
		{
			Method: http.MethodGet,
			Path:   "/api/v1/items",
			Code:   http.StatusOK,
		},
	}...)
}

// TestValidateRequest_PathParameters verifies that OAS validateRequest works
// correctly with path parameters.
func TestValidateRequest_PathParameters(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const oasSpec = `{
		"openapi": "3.0.0",
		"info": {"title": "Path Params Test", "version": "1.0.0"},
		"paths": {
			"/users/{id}": {
				"get": {
					"operationId": "getuser",
					"parameters": [
						{
							"name": "id",
							"in": "path",
							"required": true,
							"schema": {"type": "integer"}
						},
						{
							"name": "X-Request-ID",
							"in": "header",
							"required": true,
							"schema": {"type": "string"}
						}
					],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
	assert.NoError(t, err)

	oasAPI := oas.OAS{T: *oasDoc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getuser": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled:           true,
						ErrorResponseCode: http.StatusUnprocessableEntity,
					},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Path Params Validate Test"
		spec.APIID = "pathparams-validate-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// Valid path parameter, missing header
		{
			Method:    http.MethodGet,
			Path:      "/api/users/123",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `X-Request-ID`,
		},
		// Valid path parameter, header present
		{
			Method:  http.MethodGet,
			Path:    "/api/users/123",
			Headers: map[string]string{"X-Request-ID": "req-123"},
			Code:    http.StatusOK,
		},
		// Invalid path parameter type (string instead of integer)
		{
			Method:    http.MethodGet,
			Path:      "/api/users/abc",
			Headers:   map[string]string{"X-Request-ID": "req-123"},
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: `id`,
		},
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

func TestValidateRequest_EndpointCollision(t *testing.T) {
	t.Run("case 1 basic test-case from the ticket TT-16890 /employees/static is matched /employees/\\d+ and validated against it", func(t *testing.T) {
		// client's case from the ticket https://tyktech.atlassian.net/browse/TT-16890

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/{id}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Static and Path Params Validate Test"
			spec.APIID = "static-pathparams-validate-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, _ = ts.Run(t, []test.TestCase{
			// Static path - should not be validated by the {id} schema (returns 200 from mock upstream)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusOK,
			},
			// Valid path parameter (digits)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Code:   http.StatusOK,
			},
			// Invalid path parameter (letters instead of digits)
			{
				Method:    http.MethodGet,
				Path:      "/test/employees/gg",
				Code:      422,
				BodyMatch: `request validation error`,
			},
		}...)
	})

	t.Run("case 2; additional endpoint without validation and regex /employees/{name}", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/{id}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Multiple Path Params Validate Test"
			spec.APIID = "multiple-pathparams-validate-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, _ = ts.Run(t, []test.TestCase{
			// Static path - should not be validated by the {id} schema
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusOK,
			},
			// Valid path parameter for {id} (digits)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Code:   http.StatusOK,
			},
			// Path parameter matching {name} (letters)
			// Since {name} does not have validateRequest enabled, it passes through to upstream
			{
				Method: http.MethodGet,
				Path:   "/test/employees/gg",
				Code:   http.StatusOK,
			},
		}...)
	})

	t.Run("case 3; /employees/{name} schema added for the :name param", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/{id}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Overlapping Path Params Validate Test"
			spec.APIID = "overlapping-pathparams-validate-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, _ = ts.Run(t, []test.TestCase{
			// Static path - passes to upstream (no validateRequest middleware configured for this operation)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusOK,
			},
			// Valid path parameter (digits) - passes to upstream (validation is skipped because router matches {name} which has no operation ID)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Code:   http.StatusOK,
			},
			// Invalid path parameter (letters instead of digits) - passes to upstream (validation is skipped because router matches {name} which has no operation ID)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/aaa",
				Code:   http.StatusOK,
			},
		}...)
	})

	t.Run("case 4; /employees/{name} schema added for the :name param and validate reqeust middleware", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
					"operationId": "employees/{name}get",
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[a-z]+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/{id}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
					"employees/{name}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 4 Test"
			spec.APIID = "case-4-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusOK,
			},
			{
				// fails on release-5.11 with error code 422
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Code:   http.StatusOK,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/employees/asd",
				Code:   http.StatusOK,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/employees/asd123",
				Code:   http.StatusUnprocessableEntity,
			},
		}...)
	})

	t.Run("case 5; Allow List (WhiteList) Activation", func(t *testing.T) {
		// 1. Allow List (WhiteList) Activation:
		// The mission briefing explicitly states [allow mw] is configured.
		// However, the tests in the patch do not enable the Allow List middleware.
		// In Case 4, the test for /test/employees/asd123 returns 200 OK (with the comment // imo it should not pass).
		// The reason it passes is that without the Allow List enabled, the Gateway simply proxies unknown paths.
		// To properly test the expectation, you must enable the Allow List.
		// This ensures paths not matching any defined regex return a 403 Forbidden.

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
					"operationId": "employees/{name}get",
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[a-z]+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/{id}get": {
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 5 Test"
			spec.APIID = "case-5-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true

			// --- Auth Layer Configuration ---
			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			authConf := apidef.AuthConfig{
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf
			// --------------------------------

			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		// Create a session (token) with access to the API
		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				"case-5-test": {
					APIID: "case-5-test",
				},
			}
		})

		auth := map[string]string{
			"Authorization": key,
		}

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/static",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/123",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/asd",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/asd123",
				Headers: auth,
				Code:    http.StatusOK,
			},
			// Verify auth layer is active (no token provided)
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusUnauthorized,
			},
		}...)
	})

	t.Run("case 6; Dual ValidateRequest Deployment", func(t *testing.T) {
		// 2. Dual ValidateRequest Deployment:
		// In the second example, both /employees/{id:\d+} and /employees/{name:[a-z]+} have [validate request mw] enabled.
		// The current patch only has ValidateRequest enabled on the {id} operation.
		// A test case must be added where both operations have ValidateRequest enabled
		// to ensure the router applies the correct schema based on the matched regex.

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
                    "operationId": "employees/{name}get",
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[a-z]+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/staticget": {
						Allow: &oas.Allowance{Enabled: true},
					},
					"employees/{id}get": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
					"employees/{name}get": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 6 Test"
			spec.APIID = "case-6-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true

			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			authConf := apidef.AuthConfig{
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf

			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				"case-6-test": {
					APIID: "case-6-test",
				},
			}
		})

		auth := map[string]string{
			"Authorization": key,
		}

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/static",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				// fails on release-5.11 with error code 422
				Method:  http.MethodGet,
				Path:    "/test/employees/123",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				Method:  http.MethodGet,
				Path:    "/test/employees/asd",
				Headers: auth,
				Code:    http.StatusOK,
			},
			{
				// fails on release-5.11 with error code 422
				Method:  http.MethodGet,
				Path:    "/test/employees/asd123",
				Headers: auth,
				Code:    403,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Code:   http.StatusUnauthorized,
			},
		}...)
	})

	t.Run("case 7; Regex Matching the Static Path", func(t *testing.T) {
		// 3. Regex Matching the Static Path:
		// What happens if the regex for a path parameter matches the static path string?
		// For example, the regex ^[a-z]+$ for {name} will match the string static in /employees/static.
		// A test case should verify that the static path strictly
		// takes precedence over the regex path, even when the regex is a valid match.

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "get": {
                    "operationId": "employees/staticget",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "employees/{id}get",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{name}": {
                "get": {
                    "operationId": "employees/{name}get",
                    "parameters": [
                        {
                            "name": "name",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^[a-z]+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"employees/staticget": {
						Allow: &oas.Allowance{Enabled: true},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "static"}`,
						},
					},
					"employees/{id}get": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "id"}`,
						},
					},
					"employees/{name}get": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "name"}`,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 7 Test"
			spec.APIID = "case-7-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true

			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			authConf := apidef.AuthConfig{
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf

			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				"case-7-test": {
					APIID: "case-7-test",
				},
			}
		})

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `{"matched": "static"}`,
			},
			{
				// fails on release-5.11 with status code 422
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `{"matched": "id"}`,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/employees/asd",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `{"matched": "name"}`,
			},
			{
				// fails on release-5.11 with status code 422
				Method: http.MethodGet,
				Path:   "/test/employees/asd123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code: 403,
			},
		}...)
	})

	t.Run("case 8; Nested Parameterized Routes", func(t *testing.T) {
		// 4. Nested Parameterized Routes:
		// Test path ordering when there are multiple path parameters in the same route. For example:
		// • /departments/{dept}/employees/static
		// • /departments/{dept}/employees/{id}

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/departments/{dept}/employees/static": {
                "get": {
                    "operationId": "departments/{dept}/employees/staticget",
                    "parameters": [
                        {
                            "name": "dept",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            },
            "/departments/{dept}/employees/{id}": {
                "get": {
                    "operationId": "departments/{dept}/employees/{id}get",
                    "parameters": [
                        {
                            "name": "dept",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        },
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"departments/{dept}/employees/staticget": {
						Allow: &oas.Allowance{Enabled: true},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "static"}`,
						},
					},
					"departments/{dept}/employees/{id}get": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "id"}`,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 8 Test"
			spec.APIID = "case-8-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true

			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			authConf := apidef.AuthConfig{
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf

			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				"case-8-test": {
					APIID: "case-8-test",
				},
			}
		})

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/test/departments/hr/employees/static",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `"matched": "static"`,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/departments/hr/employees/123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `"matched": "id"`,
			},
			{
				// fails on release-5.11 with status code 422
				Method: http.MethodGet,
				Path:   "/test/departments/hr/employees/asd",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code: 403, // Blocked by AllowList since 'asd' doesn't match the '^\d+$' regex
			},
		}...)
	})

	t.Run("case 9; Cross-Method Overlap", func(t *testing.T) {
		// 5. Cross-Method Overlap:
		// Test overlapping paths with different HTTP methods (e.g., GET /employees/{id} vs POST /employees/static).
		// This ensures the router doesn't incorrectly apply validation
		// or routing logic across different methods for the same path structure.
		// Regarding your question on logical validity: Affirmative, the cases are valid. GET /employees/pepe123 should
		// not be rejected because it doesn't match \d+ or [a-z]+.
		// However, it will only be rejected if the Allow List middleware is enabled.
		// New construction options are available.
		// Let me know when you are ready to deploy these tests. For the Union!

		ts := StartTest(nil)
		defer ts.Close()

		const oasSpec = `{
        "openapi": "3.0.3",
        "info": {"title": "test", "version": "1.0.0"},
        "paths": {
            "/employees/static": {
                "post": {
                    "operationId": "postEmployeesStatic",
                    "responses": {"200": {"description": ""}}
                }
            },
            "/employees/{id}": {
                "get": {
                    "operationId": "getEmployeesId",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "pattern": "^\\d+$"
                            }
                        }
                    ],
                    "responses": {"200": {"description": ""}}
                }
            }
        }
    }`

		oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasSpec))
		assert.NoError(t, err)

		oasAPI := oas.OAS{T: *oasDoc}
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"postEmployeesStatic": {
						Allow: &oas.Allowance{Enabled: true},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "post_static"}`,
						},
					},
					"getEmployeesId": {
						Allow: &oas.Allowance{Enabled: true},
						ValidateRequest: &oas.ValidateRequest{
							Enabled:           true,
							ErrorResponseCode: 422,
						},
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"matched": "get_id"}`,
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "Case 9 Test"
			spec.APIID = "case-9-test"
			spec.Proxy.ListenPath = "/test/"
			spec.Proxy.StripListenPath = true

			spec.UseKeylessAccess = false
			spec.UseStandardAuth = true
			authConf := apidef.AuthConfig{
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf

			spec.IsOAS = true
			spec.OAS = oasAPI
		})

		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				"case-9-test": {
					APIID: "case-9-test",
				},
			}
		})

		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodPost,
				Path:   "/test/employees/static",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `"matched": "post_static"`,
			},
			{
				Method: http.MethodGet,
				Path:   "/test/employees/123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code:      http.StatusOK,
				BodyMatch: `"matched": "get_id"`,
			},
			{
				// fails on release-5.11 : Expected status code `403` got `200
				Method: http.MethodGet,
				Path:   "/test/employees/static",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code: 403,
			},
			{
				// fails on release-5.11 : Expected status code `403` got `200
				Method: http.MethodPost,
				Path:   "/test/employees/123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code: 403,
			},
			{
				// fails on release-5.11 : Expected status code `403` got `422
				Method: http.MethodGet,
				Path:   "/test/employees/pepe123",
				Headers: map[string]string{
					"Authorization": key,
				},
				Code: 403,
			},
		}...)
	})
}
