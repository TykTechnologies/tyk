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

	headers := map[string]string{"Content-Type": "application/json"}

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
