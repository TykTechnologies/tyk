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

func TestNormalizeHeaders(t *testing.T) {
	t.Run("single header value", func(t *testing.T) {
		headers := http.Header{
			"Content-Type": []string{"application/json"},
			"Accept":       []string{"application/json"},
		}
		normalized := normalizeHeaders(headers)
		assert.Equal(t, "application/json", normalized.Get("Content-Type"))
		assert.Equal(t, "application/json", normalized.Get("Accept"))
	})

	t.Run("multiple standard headers combined", func(t *testing.T) {
		headers := http.Header{
			"Accept":   []string{"text/html", "application/json", "application/xml"},
			"X-Custom": []string{"value1", "value2"},
		}
		normalized := normalizeHeaders(headers)
		assert.Equal(t, "text/html,application/json,application/xml", normalized.Get("Accept"))
		assert.Equal(t, "value1,value2", normalized.Get("X-Custom"))
	})

	t.Run("special headers not combined - Set-Cookie", func(t *testing.T) {
		headers := http.Header{
			"Set-Cookie": []string{"session=abc123", "user=john"},
		}
		normalized := normalizeHeaders(headers)
		// Only first value should be kept for special headers
		assert.Equal(t, "session=abc123", normalized.Get("Set-Cookie"))
		// Ensure it's not combined
		assert.NotEqual(t, "session=abc123,user=john", normalized.Get("Set-Cookie"))
	})

	t.Run("special headers not combined - WWW-Authenticate", func(t *testing.T) {
		headers := http.Header{
			"WWW-Authenticate": []string{"Basic realm=\"test\"", "Bearer realm=\"api\""},
		}
		normalized := normalizeHeaders(headers)
		assert.Equal(t, "Basic realm=\"test\"", normalized.Get("WWW-Authenticate"))
		assert.NotEqual(t, "Basic realm=\"test\",Bearer realm=\"api\"", normalized.Get("WWW-Authenticate"))
	})

	t.Run("headers with comma not combined", func(t *testing.T) {
		headers := http.Header{
			"X-Custom": []string{"value1,value2", "value3"},
		}
		normalized := normalizeHeaders(headers)
		// Should keep only first value when comma detected
		assert.Equal(t, "value1,value2", normalized.Get("X-Custom"))
		assert.NotEqual(t, "value1,value2,value3", normalized.Get("X-Custom"))
	})

	t.Run("case insensitive header names", func(t *testing.T) {
		headers := http.Header{
			"content-type": []string{"application/json"},
			"Content-Type": []string{"text/html"},
		}
		normalized := normalizeHeaders(headers)
		// Should handle case-insensitive keys properly
		val := normalized.Get("Content-Type")
		// Due to http.Header behavior, one of the values will be set
		assert.NotEmpty(t, val)
	})

	t.Run("empty header values", func(t *testing.T) {
		headers := http.Header{
			"X-Empty": []string{},
		}
		normalized := normalizeHeaders(headers)
		assert.Empty(t, normalized.Get("X-Empty"))
	})

	t.Run("mixed scenarios", func(t *testing.T) {
		headers := http.Header{
			"Accept":           []string{"text/html", "application/json"},
			"Set-Cookie":       []string{"session=abc", "user=john"},
			"Content-Type":     []string{"application/json"},
			"X-Custom-Comma":   []string{"a,b", "c"},
			"X-Custom-Regular": []string{"x", "y", "z"},
		}
		normalized := normalizeHeaders(headers)

		// Standard headers should be combined
		assert.Equal(t, "text/html,application/json", normalized.Get("Accept"))
		assert.Equal(t, "x,y,z", normalized.Get("X-Custom-Regular"))

		// Special headers should keep only first value
		assert.Equal(t, "session=abc", normalized.Get("Set-Cookie"))

		// Single value headers unchanged
		assert.Equal(t, "application/json", normalized.Get("Content-Type"))

		// Headers with commas should keep only first value
		assert.Equal(t, "a,b", normalized.Get("X-Custom-Comma"))
	})
}

func TestCloneRequestWithNormalizedHeaders(t *testing.T) {
	t.Run("clone preserves request but normalizes headers", func(t *testing.T) {
		originalHeaders := http.Header{
			"Accept":   []string{"text/html", "application/json"},
			"X-Custom": []string{"value1", "value2"},
		}

		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		assert.NoError(t, err)
		req.Header = originalHeaders

		clonedReq := cloneRequestWithNormalizedHeaders(req)

		// Original request should be unchanged
		assert.NotEqual(t, originalHeaders.Get("Accept"), "text/html,application/json")

		// Cloned request should preserve URL and method
		assert.Equal(t, "/test", clonedReq.URL.Path)
		assert.Equal(t, http.MethodGet, clonedReq.Method)

		// Cloned request headers should be normalized
		assert.Equal(t, "text/html,application/json", clonedReq.Header.Get("Accept"))
		assert.Equal(t, "value1,value2", clonedReq.Header.Get("X-Custom"))
	})

	t.Run("clone handles all header scenarios", func(t *testing.T) {
		originalHeaders := http.Header{
			"Accept":           []string{"text/html", "application/json"},
			"Set-Cookie":       []string{"session=abc", "user=john"},
			"Content-Type":     []string{"application/json"},
			"X-Custom-Comma":   []string{"a,b", "c"},
			"X-Custom-Regular": []string{"x", "y", "z"},
		}

		req, err := http.NewRequest(http.MethodPost, "/api/test", nil)
		assert.NoError(t, err)
		req.Header = originalHeaders

		clonedReq := cloneRequestWithNormalizedHeaders(req)

		// Standard headers should be combined
		assert.Equal(t, "text/html,application/json", clonedReq.Header.Get("Accept"))
		assert.Equal(t, "x,y,z", clonedReq.Header.Get("X-Custom-Regular"))

		// Special headers should keep only first value
		assert.Equal(t, "session=abc", clonedReq.Header.Get("Set-Cookie"))

		// Single value headers unchanged
		assert.Equal(t, "application/json", clonedReq.Header.Get("Content-Type"))

		// Headers with commas should keep only first value
		assert.Equal(t, "a,b", clonedReq.Header.Get("X-Custom-Comma"))
	})
}

func TestContainsComma(t *testing.T) {
	t.Run("no commas", func(t *testing.T) {
		values := []string{"value1", "value2", "value3"}
		assert.False(t, containsComma(values))
	})

	t.Run("with comma", func(t *testing.T) {
		values := []string{"value1", "value2,value3", "value4"}
		assert.True(t, containsComma(values))
	})

	t.Run("empty slice", func(t *testing.T) {
		values := []string{}
		assert.False(t, containsComma(values))
	})

	t.Run("comma in first value", func(t *testing.T) {
		values := []string{"value1,value2", "value3"}
		assert.True(t, containsComma(values))
	})

	t.Run("comma in last value", func(t *testing.T) {
		values := []string{"value1", "value2", "value3,value4"}
		assert.True(t, containsComma(values))
	})
}

func TestValidateRequest_DuplicateHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	oasWithHeaderValidation := `{
  "openapi": "3.0.0",
  "info": {
    "title": "header-validation-test",
    "version": "1.0.0"
  },
  "paths": {
    "/test": {
      "get": {
        "operationId": "getTest",
        "parameters": [{
          "name": "Accept",
          "in": "header",
          "required": false,
          "schema": {
            "type": "string"
          }
        }],
        "responses": {
          "200": {
            "description": "success"
          }
        }
      }
    }
  },
  "servers": [{"url": "/"}]
}`

	const operationID = "getTest"

	oasDoc, err := openapi3.NewLoader().LoadFromData([]byte(oasWithHeaderValidation))
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

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.VersionData = def.VersionData
		spec.OAS = oasAPI
		spec.IsOAS = true
		spec.Proxy.ListenPath = "/duplicate-header-test"
		spec.UseKeylessAccess = true
	})

	t.Run("single header value passes validation", func(t *testing.T) {
		headers := map[string]string{
			"Accept": "application/json",
		}
		_, _ = ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/duplicate-header-test/test",
			Headers: headers,
			Code:    http.StatusOK,
		})
	})

	t.Run("duplicate standard headers are normalized and pass validation", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/duplicate-header-test/test", nil)
		assert.NoError(t, err)

		req.Header.Add("Accept", "text/html")
		req.Header.Add("Accept", "application/json")

		assert.Len(t, req.Header["Accept"], 2, "Should have 2 Accept headers")

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Request with duplicate headers should pass validation after normalization")
	})
}
