package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/regexp"
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

func TestSameBasePathDifferentParamSchemas(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	// First endpoint: /employees/{prct} where prct must match ^[a-z]$, requires header "def"
	paths.Set("/employees/{prct}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByPrct",
			Parameters: openapi3.Parameters{
				{
					Value: &openapi3.Parameter{
						Name: "prct", In: "path", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    &openapi3.Types{"string"},
								Pattern: "^[a-z]$",
							},
						},
					},
				},
				{
					Value: &openapi3.Parameter{
						Name: "def", In: "header", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	// Second endpoint: /employees/{zd} where zd must match [1-9], requires header "abc"
	paths.Set("/employees/{zd}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByZd",
			Parameters: openapi3.Parameters{
				{
					Value: &openapi3.Parameter{
						Name: "zd", In: "path", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    &openapi3.Types{"string"},
								Pattern: "[1-9]",
							},
						},
					},
				},
				{
					Value: &openapi3.Parameter{
						Name: "abc", In: "header", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Same Base Path Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeByPrct": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
				"getEmployeeByZd": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Same Base Path API"
		spec.APIID = "same-base-path"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// /employees/a matches {prct} (^[a-z]$), with correct header "def" -> 200
			Method:  http.MethodGet,
			Path:    "/api/employees/a",
			Headers: map[string]string{"def": "value"},
			Code:    http.StatusOK,
		},
		{
			// /employees/5 matches {zd} ([1-9]), with correct header "abc" -> 200
			Method:  http.MethodGet,
			Path:    "/api/employees/5",
			Headers: map[string]string{"abc": "value"},
			Code:    http.StatusOK,
		},
		{
			// /employees/a matches {prct} but missing required header "def" -> 422
			Method: http.MethodGet,
			Path:   "/api/employees/a",
			Code:   http.StatusUnprocessableEntity,
		},
		{
			// /employees/5 matches {zd} but missing required header "abc" -> 422
			Method: http.MethodGet,
			Path:   "/api/employees/5",
			Code:   http.StatusUnprocessableEntity,
		},
		{
			// /employees/!!! matches neither param schema -> 422
			Method: http.MethodGet,
			Path:   "/api/employees/!!!",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

// TestDualValidateRequestWithStaticPath mirrors the python integration test
// test_dual_validate_request_on_overlapping_parameterized: two parameterized paths
// with validateRequest plus a static path without validateRequest.
func TestDualValidateRequestWithStaticPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Pattern: `^\d+$`,
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "X-Id-Header", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("Success")},
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
				{Value: &openapi3.Parameter{
					Name: "X-Name-Header", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				}},
			},
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("Success")},
			})),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses: openapi3.NewResponses(openapi3.WithStatus(200, &openapi3.ResponseRef{
				Value: &openapi3.Response{Description: stringPtrHelper("Success")},
			})),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Dual VR + Static Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByName": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getStatic": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Dual VR Static API"
		spec.APIID = "dual-vr-static"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Static path — no validateRequest, should pass through
			Method: http.MethodGet,
			Path:   "/api/employees/static",
			Code:   http.StatusOK,
		},
		{
			// "123" matches ^\d+$ ({id}), no X-Id-Header -> 400
			Method: http.MethodGet,
			Path:   "/api/employees/123",
			Code:   http.StatusBadRequest,
		},
		{
			// "123" matches ^\d+$ ({id}), with both headers -> 200
			Method:  http.MethodGet,
			Path:    "/api/employees/123",
			Headers: map[string]string{"X-Id-Header": "v", "X-Name-Header": "v"},
			Code:    http.StatusOK,
		},
		{
			// "abc" matches ^[a-z]+$ ({name}), no X-Name-Header -> 422
			Method: http.MethodGet,
			Path:   "/api/employees/abc",
			Code:   http.StatusUnprocessableEntity,
		},
		{
			// "abc" matches ^[a-z]+$ ({name}), with header -> 200
			Method:  http.MethodGet,
			Path:    "/api/employees/abc",
			Headers: map[string]string{"X-Name-Header": "v"},
			Code:    http.StatusOK,
		},
	}...)
}

// TestSameBasePathStringCatchAll reproduces the exampleOas.yaml scenario where
// type:string (no pattern) sorts alphabetically BEFORE type:number, proving that
// the string candidate steals numeric path values.
func TestSameBasePathStringCatchAll(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	// /employees/{prct} — type:string (catch-all), requires header "def"
	// Alphabetically {prct} < {zd}, so this candidate is tried first.
	paths.Set("/employees/{prct}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByPrct",
			Parameters: openapi3.Parameters{
				{
					Value: &openapi3.Parameter{
						Name: "prct", In: "path", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
				{
					Value: &openapi3.Parameter{
						Name: "def", In: "header", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	// /employees/{zd} — type:number, requires header "abc"
	// Alphabetically {zd} > {prct}, so this candidate is tried second.
	paths.Set("/employees/{zd}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByZd",
			Parameters: openapi3.Parameters{
				{
					Value: &openapi3.Parameter{
						Name: "zd", In: "path", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"number"}},
						},
					},
				},
				{
					Value: &openapi3.Parameter{
						Name: "abc", In: "header", Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "String Catch-All Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeByPrct": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
				"getEmployeeByZd": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "String Catch-All API"
		spec.APIID = "string-catch-all"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// /employees/5 with header "abc" should match {zd} (type:number) -> 200
			// BUG: {prct} (type:string) is tried first alphabetically,
			// "5" is a valid string, but header "def" is missing -> fails,
			// then {zd} is tried -> passes. This case works by accident.
			Method:  http.MethodGet,
			Path:    "/api/employees/5",
			Headers: map[string]string{"abc": "value"},
			Code:    http.StatusOK,
		},
		{
			// /employees/5 with header "def" should ideally NOT match {prct}
			// since "5" is a number and {zd} is the number endpoint.
			// BUG: {prct} (type:string) is tried first, "5" is a valid string,
			// header "def" is present -> validation passes -> 200 on WRONG endpoint.
			// This should match {zd} which requires header "abc", not "def".
			Method:  http.MethodGet,
			Path:    "/api/employees/5",
			Headers: map[string]string{"def": "value"},
			Code:    http.StatusUnprocessableEntity,
		},
	}...)
}

func TestGroupCollapsedValidateRequestSpecs(t *testing.T) {
	makeSpec := func(path, method, regex string) URLSpec {
		return URLSpec{
			Status:                 OASValidateRequest,
			OASValidateRequestMeta: &oas.ValidateRequest{Enabled: true},
			OASMethod:              method,
			OASPath:                path,
			spec:                   regexp.MustCompile(regex),
		}
	}

	t.Run("no collision leaves specs unchanged", func(t *testing.T) {
		specs := []URLSpec{
			makeSpec("/users/{id}", "GET", `^/users/([^/]+)$`),
			makeSpec("/items/{id}", "GET", `^/items/([^/]+)$`),
		}
		result := groupCollapsedValidateRequestSpecs(specs, nil)
		assert.Len(t, result, 2)
		assert.Nil(t, result[0].OASValidateRequestCandidates)
		assert.Nil(t, result[1].OASValidateRequestCandidates)
	})

	t.Run("same regex same method groups into candidates", func(t *testing.T) {
		specs := []URLSpec{
			makeSpec("/employees/{prct}", "GET", `^/employees/([^/]+)$`),
			makeSpec("/employees/{zd}", "GET", `^/employees/([^/]+)$`),
		}
		result := groupCollapsedValidateRequestSpecs(specs, nil)
		assert.Len(t, result, 1)
		assert.Len(t, result[0].OASValidateRequestCandidates, 2)
		// Candidates are sorted by OASPath
		assert.Equal(t, "/employees/{prct}", result[0].OASValidateRequestCandidates[0].OASPath)
		assert.Equal(t, "/employees/{zd}", result[0].OASValidateRequestCandidates[1].OASPath)
	})

	t.Run("same regex different methods are not grouped", func(t *testing.T) {
		specs := []URLSpec{
			makeSpec("/employees/{id}", "GET", `^/employees/([^/]+)$`),
			makeSpec("/employees/{id}", "POST", `^/employees/([^/]+)$`),
		}
		result := groupCollapsedValidateRequestSpecs(specs, nil)
		assert.Len(t, result, 2)
		assert.Nil(t, result[0].OASValidateRequestCandidates)
		assert.Nil(t, result[1].OASValidateRequestCandidates)
	})

	t.Run("three specs with same regex and method all grouped", func(t *testing.T) {
		specs := []URLSpec{
			makeSpec("/employees/{a}", "GET", `^/employees/([^/]+)$`),
			makeSpec("/employees/{b}", "GET", `^/employees/([^/]+)$`),
			makeSpec("/employees/{c}", "GET", `^/employees/([^/]+)$`),
		}
		result := groupCollapsedValidateRequestSpecs(specs, nil)
		assert.Len(t, result, 1)
		assert.Len(t, result[0].OASValidateRequestCandidates, 3)
		assert.Equal(t, "/employees/{a}", result[0].OASValidateRequestCandidates[0].OASPath)
		assert.Equal(t, "/employees/{b}", result[0].OASValidateRequestCandidates[1].OASPath)
		assert.Equal(t, "/employees/{c}", result[0].OASValidateRequestCandidates[2].OASPath)
	})
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
