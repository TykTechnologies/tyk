package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

func TestSortURLSpecsByPathPriority(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected []string
	}{
		{
			name:     "static path before parameterised",
			paths:    []string{"/employees/{id}", "/employees/static"},
			expected: []string{"/employees/static", "/employees/{id}"},
		},
		{
			name:     "more segments first",
			paths:    []string{"/a/b", "/a/b/c"},
			expected: []string{"/a/b/c", "/a/b"},
		},
		{
			name:     "longer path first",
			paths:    []string{"/api/user", "/api/user-access"},
			expected: []string{"/api/user-access", "/api/user"},
		},
		{
			name:     "alphabetical for equal length",
			paths:    []string{"/api/abc", "/api/aba"},
			expected: []string{"/api/aba", "/api/abc"},
		},
		{
			name: "multiple mixed paths",
			paths: []string{
				"/users/{id}",
				"/users/me",
				"/users/{id}/reports",
				"/departments/{deptId}",
			},
			expected: []string{
				"/users/{id}/reports",
				"/departments/{deptId}",
				"/users/me",
				"/users/{id}",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			specs := make([]URLSpec, len(tc.paths))
			for i, p := range tc.paths {
				specs[i] = URLSpec{OASPath: p}
			}

			sortURLSpecsByPathPriority(specs)

			got := make([]string, len(specs))
			for i, s := range specs {
				got[i] = s.OASPath
			}

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestStaticPathTakesPrecedenceOverParameterised(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticEmployee",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     "id",
						In:       "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    &openapi3.Types{"string"},
								Pattern: "^[a-zA-Z]+$",
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Validate Request Priority Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getStaticEmployee": {},
				"getEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Validate Request Priority API"
		spec.APIID = "validate-request-priority"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method: http.MethodGet,
			Path:   "/api/employees/static",
			Code:   http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/api/employees/john",
			Code:   http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/api/employees/123",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestMockResponseStaticPathPriority(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/items/special", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getSpecialItem",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	paths.Set("/items/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getItemById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     "id",
						In:       "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string"},
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Mock Response Priority Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getSpecialItem": {},
				"getItemById": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: "mocked"},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Mock Response Priority API"
		spec.APIID = "mock-response-priority"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Static path should NOT get mock response — the mock is only on {id}
			Method:       http.MethodGet,
			Path:         "/api/items/special",
			BodyNotMatch: "mocked",
		},
		{
			// Parameterised path should get mock response
			Method:    http.MethodGet,
			Path:      "/api/items/123",
			Code:      http.StatusOK,
			BodyMatch: "mocked",
		},
	}...)
}

func TestStaticPathPriorityWithPrefixMatching(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Enable prefix matching at gateway level
	conf := ts.Gw.GetConfig()
	conf.HttpServerOptions.EnablePathPrefixMatching = true
	ts.Gw.SetConfig(conf)

	paths := openapi3.NewPaths()

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticEmployee",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     "X-Custom-Header",
						In:       "header",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string"},
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     "id",
						In:       "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    &openapi3.Types{"string"},
								Pattern: "^[a-zA-Z]+$",
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Prefix Matching Priority Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getStaticEmployee": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
				"getEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Prefix Matching Priority API"
		spec.APIID = "prefix-matching-priority"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Static path without required header should fail its OWN validation,
			// proving it matched /employees/static and not /employees/{id}
			Method:    http.MethodGet,
			Path:      "/api/employees/static",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: "X-Custom-Header",
		},
		{
			// Static path with required header should pass validation
			Method:  http.MethodGet,
			Path:    "/api/employees/static",
			Code:    http.StatusOK,
			Headers: map[string]string{"X-Custom-Header": "value"},
		},
		{
			// Parameterised path with valid id should pass
			Method: http.MethodGet,
			Path:   "/api/employees/john",
			Code:   http.StatusOK,
		},
		{
			// Parameterised path with invalid id should fail
			Method: http.MethodGet,
			Path:   "/api/employees/123",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}
