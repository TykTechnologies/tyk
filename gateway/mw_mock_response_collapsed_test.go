package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestMockResponseCollapsedParamsByType tests that two parameterized paths with
// different mock responses are disambiguated by path parameter type.
// /employees/{id} (type:integer) should return "numeric" mock,
// /employees/{name} (type:string, pattern:^[a-z]+$) should return "alpha" mock.
func TestMockResponseCollapsedParamsByType(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	paths.Set("/employees/{name}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByName",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "name", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Pattern: `^[a-z]+$`,
					}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Mock Collapsed By Type", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"numeric"}`},
				},
				"getByName": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"alpha"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Mock Collapsed By Type"
		spec.APIID = "mock-collapsed-type"
		spec.Proxy.ListenPath = "/test-mock-type/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// 42 is an integer -> should return "numeric" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-type/employees/42",
			Code:      http.StatusOK,
			BodyMatch: `"source":"numeric"`,
		},
		{
			// "alice" matches ^[a-z]+$ -> should return "alpha" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-type/employees/alice",
			Code:      http.StatusOK,
			BodyMatch: `"source":"alpha"`,
		},
	}...)
}

// TestMockResponseCollapsedParamsByPattern tests that two string-typed parameterized
// paths with different patterns return the correct mock response.
func TestMockResponseCollapsedParamsByPattern(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "code", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`,
					}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	paths.Set("/employees/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "slug", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Mock Collapsed By Pattern", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByCode": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"code"}`},
				},
				"getBySlug": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"slug"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Mock Collapsed By Pattern"
		spec.APIID = "mock-collapsed-pattern"
		spec.Proxy.ListenPath = "/test-mock-pattern/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// "ABC" matches ^[A-Z]{3}$ -> should return "code" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-pattern/employees/ABC",
			Code:      http.StatusOK,
			BodyMatch: `"source":"code"`,
		},
		{
			// "hello" doesn't match ^[A-Z]{3}$ -> falls to unconstrained string -> "slug" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-pattern/employees/hello",
			Code:      http.StatusOK,
			BodyMatch: `"source":"slug"`,
		},
	}...)
}

// TestMockResponseCollapsedWithStaticPath tests that the static path shield still
// works when two parameterized paths collapse to the same regex with different mocks.
func TestMockResponseCollapsedWithStaticPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	paths.Set("/employees/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "slug", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("OK")},
			})),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Mock Collapsed With Static", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"numeric"}`},
				},
				"getBySlug": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"source":"slug"}`},
				},
				"getStatic": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Mock Collapsed With Static"
		spec.APIID = "mock-collapsed-static"
		spec.Proxy.ListenPath = "/test-mock-static/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Static path — no mock, proxies to upstream
			Method:       http.MethodGet,
			Path:         "/test-mock-static/employees/static",
			Code:         http.StatusOK,
			BodyNotMatch: `"source"`,
		},
		{
			// 42 is integer -> "numeric" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-static/employees/42",
			Code:      http.StatusOK,
			BodyMatch: `"source":"numeric"`,
		},
		{
			// "hello" -> falls to unconstrained string -> "slug" mock
			Method:    http.MethodGet,
			Path:      "/test-mock-static/employees/hello",
			Code:      http.StatusOK,
			BodyMatch: `"source":"slug"`,
		},
	}...)
}
