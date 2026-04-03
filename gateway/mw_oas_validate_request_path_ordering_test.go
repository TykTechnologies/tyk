package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

func TestOASValidateRequestPathOrdering(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS with two paths:
	// 1. /users/{id} - parameterized, with ValidateRequest enabled
	// 2. /users/admin - static, without ValidateRequest
	paths := openapi3.NewPaths()
	
	// Parameterized path
	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "id",
						In:   "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"integer"},
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	// Static path
	paths.Set("/users/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAdminUser",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   "Test API",
			Version: "1.0.0",
		},
		Paths: paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled: true,
					},
				},
				// getAdminUser has no ValidateRequest
			},
		},
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "OAS Path Ordering Test"
		spec.APIID = "oas-path-ordering-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	require.NotNil(t, api)
	require.True(t, api.IsOAS)

	// Test 1: Parameterized path with invalid param (should fail validation)
	// Test 2: Static path (should bypass validation and return 200/404 depending on upstream, but not 422)
	_, _ = ts.Run(t, []test.TestCase{
		{
			Code:   http.StatusUnprocessableEntity,
			Method: http.MethodGet,
			Path:   "/api/users/not-an-int",
		},
		{
			Code:   http.StatusOK, // The mock upstream returns 200
			Method: http.MethodGet,
			Path:   "/api/users/admin",
		},
	}...)
}

func TestOASMockResponsePathOrdering(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS with two paths:
	// 1. /users/{id} - parameterized, with MockResponse enabled
	// 2. /users/admin - static, without MockResponse
	paths := openapi3.NewPaths()
	
	// Parameterized path
	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "id",
						In:   "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"integer"},
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	// Static path
	paths.Set("/users/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAdminUser",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   "Test API",
			Version: "1.0.0",
		},
		Paths: paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    200,
						Body:    `{"mocked": true}`,
					},
				},
				// getAdminUser has no MockResponse
			},
		},
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "OAS Path Ordering Test"
		spec.APIID = "oas-path-ordering-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	require.NotNil(t, api)
	require.True(t, api.IsOAS)

	// Test 1: Parameterized path (should return mock response)
	// Test 2: Static path (should bypass mock response and return 200 from upstream, without mock body)
	_, _ = ts.Run(t, []test.TestCase{
		{
			Code:      http.StatusOK,
			Method:    http.MethodGet,
			Path:      "/api/users/123",
			BodyMatch: `{"mocked": true}`,
		},
		{
			Code:         http.StatusOK,
			Method:       http.MethodGet,
			Path:         "/api/users/admin",
			BodyNotMatch: `{"mocked": true}`,
		},
	}...)
}
