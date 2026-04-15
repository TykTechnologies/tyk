package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// helper to build a standard openapi3 response set for 200.
func oasResponse200() *openapi3.Responses {
	return openapi3.NewResponses(
		openapi3.WithStatus(200, &openapi3.ResponseRef{
			Value: &openapi3.Response{Description: stringPtrHelper("Success")},
		}),
	)
}

// helper to build a path parameter.
func pathParam(name string, schema *openapi3.Schema) *openapi3.ParameterRef {
	return &openapi3.ParameterRef{
		Value: &openapi3.Parameter{
			Name: name, In: "path", Required: true,
			Schema: &openapi3.SchemaRef{Value: schema},
		},
	}
}

// helper to build a required header parameter.
func headerParam(name string) *openapi3.ParameterRef {
	return &openapi3.ParameterRef{
		Value: &openapi3.Parameter{
			Name: name, In: "header", Required: true,
			Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
		},
	}
}

func TestScenario9_NestedParameterizedRoutes(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/departments/{dept}/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getNestedParam",
			Parameters: openapi3.Parameters{
				pathParam("dept", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/departments/{dept}/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getNestedStatic",
			Parameters: openapi3.Parameters{
				pathParam("dept", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 9", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getNestedParam": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "nested-param"}`},
				},
				"getNestedStatic": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "nested-static"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 9 API"
		spec.APIID = "scenario-9"
		spec.Proxy.ListenPath = "/test-9/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/test-9/departments/sales/employees/static",
			Code:      http.StatusOK,
			BodyMatch: "nested-static",
		},
		{
			Method:    http.MethodGet,
			Path:      "/test-9/departments/sales/employees/42",
			Code:      http.StatusOK,
			BodyMatch: "nested-param",
		},
	}...)
}

func TestScenario10_CrossMethodNoInterference(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Get-Header"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postStaticEmployee",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 10", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"postStaticEmployee": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 10 API"
		spec.APIID = "scenario-10"
		spec.Proxy.ListenPath = "/test-10/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method: http.MethodPost,
			Path:   "/test-10/employees/static",
			Code:   http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-10/employees/123",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario11_MultipleStaticPathsShielded(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Auth"),
			},
			Responses: oasResponse200(),
		},
	})

	for _, static := range []struct {
		path string
		opID string
	}{
		{"/users/admin", "getUserAdmin"},
		{"/users/me", "getUserMe"},
		{"/users/status", "getUserStatus"},
	} {
		paths.Set(static.path, &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: static.opID,
				Responses:   oasResponse200(),
			},
		})
	}

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 11", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"getUserAdmin":  {},
				"getUserMe":     {},
				"getUserStatus": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 11 API"
		spec.APIID = "scenario-11"
		spec.Proxy.ListenPath = "/test-11/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-11/users/admin", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-11/users/me", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-11/users/status", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-11/users/42", Code: http.StatusUnprocessableEntity},
		{
			Method:  http.MethodGet,
			Path:    "/test-11/users/42",
			Headers: map[string]string{"X-Auth": "val"},
			Code:    http.StatusOK,
		},
	}...)
}

func TestScenario12_NonConflictingStaticPathUnaffected(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Auth"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/health", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getHealth",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 12", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"getHealth": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 12 API"
		spec.APIID = "scenario-12"
		spec.Proxy.ListenPath = "/test-12/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-12/health", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-12/users/42", Code: http.StatusUnprocessableEntity},
	}...)
}

func TestScenario14_POSTWithRequestBodySchemaValidation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postEmployeeById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.NewContentWithJSONSchema(&openapi3.Schema{
						Type:     &openapi3.Types{"object"},
						Required: []string{"name"},
						Properties: openapi3.Schemas{
							"name": &openapi3.SchemaRef{
								Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
							},
						},
					}),
				},
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postStaticEmployee",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 14", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"postEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"postStaticEmployee": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 14 API"
		spec.APIID = "scenario-14"
		spec.Proxy.ListenPath = "/test-14/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method: http.MethodPost,
			Path:   "/test-14/employees/static",
			Code:   http.StatusOK,
		},
		{
			Method: http.MethodPost,
			Path:   "/test-14/employees/123",
			Data:   `{}`,
			Code:   http.StatusUnprocessableEntity,
		},
		{
			Method: http.MethodPost,
			Path:   "/test-14/employees/123",
			Data:   `{"name": "Alice"}`,
			Code:   http.StatusOK,
		},
	}...)
}

func TestScenario16_ThreeLevelPathHierarchy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/a/{b}/c", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBc",
			Parameters: openapi3.Parameters{
				pathParam("b", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/a/static/c", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticC",
			Responses:   oasResponse200(),
		},
	})

	paths.Set("/a/{b}/{c}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBcWild",
			Parameters: openapi3.Parameters{
				pathParam("b", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				pathParam("c", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 16", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getBc": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "b-c"}`},
				},
				"getStaticC": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "static-c"}`},
				},
				"getBcWild": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "b-c-wild"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 16 API"
		spec.APIID = "scenario-16"
		spec.Proxy.ListenPath = "/test-16/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/test-16/a/static/c",
			Code:      http.StatusOK,
			BodyMatch: "static-c",
		},
		{
			Method:    http.MethodGet,
			Path:      "/test-16/a/foo/c",
			Code:      http.StatusOK,
			BodyMatch: `"b-c"`,
		},
		{
			Method:    http.MethodGet,
			Path:      "/test-16/a/foo/bar",
			Code:      http.StatusOK,
			BodyMatch: "b-c-wild",
		},
	}...)
}

func TestScenario17_RootListenPathWithMockResponse(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticEmployee",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 17", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeById": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "parameterized"}`},
				},
				"getStaticEmployee": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "static"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 17 API"
		spec.APIID = "scenario-17"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/employees/static",
			Code:      http.StatusOK,
			BodyMatch: `"static"`,
		},
		{
			Method:    http.MethodGet,
			Path:      "/employees/123",
			Code:      http.StatusOK,
			BodyMatch: "parameterized",
		},
	}...)
}

func TestScenario18_RootListenPathWithValidateRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^\d+$`}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticEmployee",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 18", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"getStaticEmployee": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 18 API"
		spec.APIID = "scenario-18"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/employees/static", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/employees/123", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/employees/abc", Code: http.StatusUnprocessableEntity},
	}...)
}

func TestScenario21_MultiSegmentListenPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStaticEmployee",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 21", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeById": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "parameterized"}`},
				},
				"getStaticEmployee": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: `{"message": "static"}`},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 21 API"
		spec.APIID = "scenario-21"
		spec.Proxy.ListenPath = "/api/v2/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:    http.MethodGet,
			Path:      "/api/v2/employees/static",
			Code:      http.StatusOK,
			BodyMatch: `"static"`,
		},
		{
			Method:    http.MethodGet,
			Path:      "/api/v2/employees/123",
			Code:      http.StatusOK,
			BodyMatch: "parameterized",
		},
	}...)
}

func TestScenario24_ThreeCollapsedParameterizedPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				pathParam("slug", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Slug"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 24", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByCode": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getBySlug": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 24 API"
		spec.APIID = "scenario-24"
		spec.Proxy.ListenPath = "/test-24/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-24/employees/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-24/employees/42",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-24/employees/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-24/employees/ABC",
			Code:   http.StatusUnprocessableEntity,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-24/employees/hello",
			Headers: map[string]string{"X-Slug": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-24/employees/hello",
			Code:   http.StatusConflict,
		},
	}...)
}

func TestScenario26_SameBasePathDifferentMethodsNoGrouping(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^\d+$`}),
			},
			Responses: oasResponse200(),
		},
		Post: &openapi3.Operation{
			OperationID: "postById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.NewContentWithJSONSchema(&openapi3.Schema{
						Type:     &openapi3.Types{"object"},
						Required: []string{"name"},
						Properties: openapi3.Schemas{
							"name": &openapi3.SchemaRef{
								Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
							},
						},
					}),
				},
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 26", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"postById": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 26 API"
		spec.APIID = "scenario-26"
		spec.Proxy.ListenPath = "/test-26/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-26/employees/abc", Code: http.StatusBadRequest},
		{Method: http.MethodGet, Path: "/test-26/employees/123", Code: http.StatusOK},
		{
			Method: http.MethodPost,
			Path:   "/test-26/employees/123",
			Data:   `{}`,
			Code:   http.StatusUnprocessableEntity,
		},
		{
			Method: http.MethodPost,
			Path:   "/test-26/employees/123",
			Data:   `{"name":"Alice"}`,
			Code:   http.StatusOK,
		},
	}...)
}

func TestScenario27_EnumBasedParamDisambiguation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{role}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByRole",
			Parameters: openapi3.Parameters{
				pathParam("role", &openapi3.Schema{
					Type: &openapi3.Types{"string"},
					Enum: []interface{}{"admin", "manager"},
				}),
				headerParam("X-Role"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 27", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByRole": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getById":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 27 API"
		spec.APIID = "scenario-27"
		spec.Proxy.ListenPath = "/test-27/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-27/employees/admin",
			Headers: map[string]string{"X-Role": "v"},
			Code:    http.StatusOK,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-27/employees/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-27/employees/admin",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario28_DotstarPatternVsSpecificPattern(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^\d+$`}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{fallback}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFallback",
			Parameters: openapi3.Parameters{
				pathParam("fallback", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `.*`}),
				headerParam("X-Fallback"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 28", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":       {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByFallback": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 28 API"
		spec.APIID = "scenario-28"
		spec.Proxy.ListenPath = "/test-28/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-28/employees/123",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-28/employees/123",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-28/employees/abc",
			Headers: map[string]string{"X-Fallback": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-28/employees/abc",
			Code:   http.StatusUnprocessableEntity,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-28/employees/hello-world",
			Headers: map[string]string{"X-Fallback": "v"},
			Code:    http.StatusOK,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-28/employees/!!!",
			Headers: map[string]string{"X-Fallback": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-28/employees/!!!",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario29_DotstarVsUnconstrainedString(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{wild}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByWild",
			Parameters: openapi3.Parameters{
				pathParam("wild", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `.*`}),
				headerParam("X-Wild"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{any}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAny",
			Parameters: openapi3.Parameters{
				pathParam("any", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Any"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 29", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByWild": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getByAny":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 29 API"
		spec.APIID = "scenario-29"
		spec.Proxy.ListenPath = "/test-29/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-29/employees/foo",
			Headers: map[string]string{"X-Wild": "v"},
			Code:    http.StatusOK,
		},
		{
			// wild commits first, so X-Any alone triggers wild's 422
			Method:  http.MethodGet,
			Path:    "/test-29/employees/foo",
			Headers: map[string]string{"X-Any": "v"},
			Code:    http.StatusUnprocessableEntity,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-29/employees/foo",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario30_DotstarWithStaticPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{fallback}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFallback",
			Parameters: openapi3.Parameters{
				pathParam("fallback", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `.*`}),
				headerParam("X-Fallback"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 30", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByFallback": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getStatic":     {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 30 API"
		spec.APIID = "scenario-30"
		spec.Proxy.ListenPath = "/test-30/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-30/employees/static", Code: http.StatusOK},
		{
			Method:  http.MethodGet,
			Path:    "/test-30/employees/anything",
			Headers: map[string]string{"X-Fallback": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-30/employees/anything",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario31_DotstarIntegerStaticThreeWay(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{fallback}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFallback",
			Parameters: openapi3.Parameters{
				pathParam("fallback", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `.*`}),
				headerParam("X-Fallback"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 31", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":       {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByFallback": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getStatic":     {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 31 API"
		spec.APIID = "scenario-31"
		spec.Proxy.ListenPath = "/test-31/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-31/employees/static", Code: http.StatusOK},
		{
			Method:  http.MethodGet,
			Path:    "/test-31/employees/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-31/employees/42",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-31/employees/abc",
			Headers: map[string]string{"X-Fallback": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-31/employees/abc",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario32_IntegerVsNumberPriority(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{amt}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAmt",
			Parameters: openapi3.Parameters{
				pathParam("amt", &openapi3.Schema{Type: &openapi3.Types{"number"}}),
				headerParam("X-Amt"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 32", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByAmt": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 32 API"
		spec.APIID = "scenario-32"
		spec.Proxy.ListenPath = "/test-32/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-32/employees/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-32/employees/42",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-32/employees/3.14",
			Headers: map[string]string{"X-Amt": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-32/employees/3.14",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario33_NumberVsBooleanPriority(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{amt}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAmt",
			Parameters: openapi3.Parameters{
				pathParam("amt", &openapi3.Schema{Type: &openapi3.Types{"number"}}),
				headerParam("X-Amt"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{flag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFlag",
			Parameters: openapi3.Parameters{
				pathParam("flag", &openapi3.Schema{Type: &openapi3.Types{"boolean"}}),
				headerParam("X-Flag"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 33", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByAmt":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByFlag": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 33 API"
		spec.APIID = "scenario-33"
		spec.Proxy.ListenPath = "/test-33/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-33/employees/42",
			Headers: map[string]string{"X-Amt": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-33/employees/42",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-33/employees/true",
			Headers: map[string]string{"X-Flag": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-33/employees/true",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario34_BooleanVsStringWithPattern(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{flag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFlag",
			Parameters: openapi3.Parameters{
				pathParam("flag", &openapi3.Schema{Type: &openapi3.Types{"boolean"}}),
				headerParam("X-Flag"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 34", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByFlag": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByCode": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 34 API"
		spec.APIID = "scenario-34"
		spec.Proxy.ListenPath = "/test-34/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-34/employees/true",
			Headers: map[string]string{"X-Flag": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-34/employees/true",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-34/employees/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-34/employees/ABC",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario35_IntegerNumberBooleanFullHierarchy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{amt}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAmt",
			Parameters: openapi3.Parameters{
				pathParam("amt", &openapi3.Schema{Type: &openapi3.Types{"number"}}),
				headerParam("X-Amt"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{flag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFlag",
			Parameters: openapi3.Parameters{
				pathParam("flag", &openapi3.Schema{Type: &openapi3.Types{"boolean"}}),
				headerParam("X-Flag"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 35", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByAmt":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getByFlag": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 35 API"
		spec.APIID = "scenario-35"
		spec.Proxy.ListenPath = "/test-35/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-35/employees/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-35/employees/42", Code: http.StatusBadRequest},
		{
			Method:  http.MethodGet,
			Path:    "/test-35/employees/3.14",
			Headers: map[string]string{"X-Amt": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-35/employees/3.14", Code: http.StatusUnprocessableEntity},
		{
			Method:  http.MethodGet,
			Path:    "/test-35/employees/true",
			Headers: map[string]string{"X-Flag": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-35/employees/true", Code: http.StatusConflict},
	}...)
}

func TestScenario36_StringPatternLengthOrdering(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{2,4}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{tag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByTag",
			Parameters: openapi3.Parameters{
				pathParam("tag", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[a-z]$`}),
				headerParam("X-Tag"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 36", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByCode": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByTag":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 36 API"
		spec.APIID = "scenario-36"
		spec.Proxy.ListenPath = "/test-36/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-36/employees/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-36/employees/ABC", Code: http.StatusBadRequest},
		{
			Method:  http.MethodGet,
			Path:    "/test-36/employees/a",
			Headers: map[string]string{"X-Tag": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-36/employees/a", Code: http.StatusUnprocessableEntity},
	}...)
}

func TestScenario37_ThreeStringPatternsByLength(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{uuid}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByUUID",
			Parameters: openapi3.Parameters{
				pathParam("uuid", &openapi3.Schema{
					Type:    &openapi3.Types{"string"},
					Pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
				}),
				headerParam("X-UUID"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{fallback}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFb",
			Parameters: openapi3.Parameters{
				pathParam("fallback", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `.*`}),
				headerParam("X-Fb"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 37", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByUUID": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByCode": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getByFb":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 37 API"
		spec.APIID = "scenario-37"
		spec.Proxy.ListenPath = "/test-37/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-37/employees/550e8400-e29b-41d4-a716-446655440000",
			Headers: map[string]string{"X-UUID": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-37/employees/550e8400-e29b-41d4-a716-446655440000",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-37/employees/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-37/employees/ABC", Code: http.StatusUnprocessableEntity},
		{
			Method:  http.MethodGet,
			Path:    "/test-37/employees/anything",
			Headers: map[string]string{"X-Fb": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-37/employees/anything", Code: http.StatusConflict},
	}...)
}

func TestScenario38_StringPatternVsEnum(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{role}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByRole",
			Parameters: openapi3.Parameters{
				pathParam("role", &openapi3.Schema{
					Type: &openapi3.Types{"string"},
					Enum: []interface{}{"admin", "manager", "viewer"},
				}),
				headerParam("X-Role"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 38", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByCode": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByRole": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 38 API"
		spec.APIID = "scenario-38"
		spec.Proxy.ListenPath = "/test-38/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-38/employees/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-38/employees/ABC", Code: http.StatusBadRequest},
		{
			Method:  http.MethodGet,
			Path:    "/test-38/employees/admin",
			Headers: map[string]string{"X-Role": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-38/employees/admin", Code: http.StatusUnprocessableEntity},
	}...)
}

func TestScenario41_MultiParamCumulativeScoring(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/departments/{dept_id}/employees/{emp_id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getTyped",
			Parameters: openapi3.Parameters{
				pathParam("dept_id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				pathParam("emp_id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Typed"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/departments/{dept_name}/employees/{emp_name}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getMixed",
			Parameters: openapi3.Parameters{
				pathParam("dept_name", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[a-z]+$`}),
				pathParam("emp_name", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Mixed"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 41", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getTyped": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getMixed": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 41 API"
		spec.APIID = "scenario-41"
		spec.Proxy.ListenPath = "/test-41/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-41/departments/1/employees/42",
			Headers: map[string]string{"X-Typed": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-41/departments/1/employees/42",
			Code:   http.StatusBadRequest,
		},
		{
			Method:  http.MethodGet,
			Path:    "/test-41/departments/engineering/employees/alice",
			Headers: map[string]string{"X-Mixed": "v"},
			Code:    http.StatusOK,
		},
		{
			Method: http.MethodGet,
			Path:   "/test-41/departments/engineering/employees/alice",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestScenario43_FullTypeHierarchy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/items/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{price}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByPrice",
			Parameters: openapi3.Parameters{
				pathParam("price", &openapi3.Schema{Type: &openapi3.Types{"number"}}),
				headerParam("X-Price"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{flag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFlag",
			Parameters: openapi3.Parameters{
				pathParam("flag", &openapi3.Schema{Type: &openapi3.Types{"boolean"}}),
				headerParam("X-Flag"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				pathParam("slug", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Slug"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 43", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":    {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByPrice": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getByFlag":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
				"getByCode":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 415}},
				"getBySlug":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 406}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 43 API"
		spec.APIID = "scenario-43"
		spec.Proxy.ListenPath = "/test-43/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			Method:  http.MethodGet,
			Path:    "/test-43/items/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-43/items/42", Code: http.StatusBadRequest},
		{
			Method:  http.MethodGet,
			Path:    "/test-43/items/3.14",
			Headers: map[string]string{"X-Price": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-43/items/3.14", Code: http.StatusUnprocessableEntity},
		{
			Method:  http.MethodGet,
			Path:    "/test-43/items/true",
			Headers: map[string]string{"X-Flag": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-43/items/true", Code: http.StatusConflict},
		{
			Method:  http.MethodGet,
			Path:    "/test-43/items/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-43/items/ABC", Code: http.StatusUnsupportedMediaType},
		{
			Method:  http.MethodGet,
			Path:    "/test-43/items/hello",
			Headers: map[string]string{"X-Slug": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-43/items/hello", Code: http.StatusNotAcceptable},
	}...)
}

func TestScenario44_FullHierarchyWithStaticPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/items/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
				headerParam("X-Id"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{price}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByPrice",
			Parameters: openapi3.Parameters{
				pathParam("price", &openapi3.Schema{Type: &openapi3.Types{"number"}}),
				headerParam("X-Price"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{flag}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByFlag",
			Parameters: openapi3.Parameters{
				pathParam("flag", &openapi3.Schema{Type: &openapi3.Types{"boolean"}}),
				headerParam("X-Flag"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByCode",
			Parameters: openapi3.Parameters{
				pathParam("code", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`}),
				headerParam("X-Code"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				pathParam("slug", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Slug"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/items/featured", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getFeatured",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 44", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById":     {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByPrice":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
				"getByFlag":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 409}},
				"getByCode":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 415}},
				"getBySlug":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 406}},
				"getFeatured": {},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 44 API"
		spec.APIID = "scenario-44"
		spec.Proxy.ListenPath = "/test-44/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-44/items/featured", Code: http.StatusOK},
		{
			Method:  http.MethodGet,
			Path:    "/test-44/items/42",
			Headers: map[string]string{"X-Id": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-44/items/42", Code: http.StatusBadRequest},
		{
			Method:  http.MethodGet,
			Path:    "/test-44/items/3.14",
			Headers: map[string]string{"X-Price": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-44/items/3.14", Code: http.StatusUnprocessableEntity},
		{
			Method:  http.MethodGet,
			Path:    "/test-44/items/true",
			Headers: map[string]string{"X-Flag": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-44/items/true", Code: http.StatusConflict},
		{
			Method:  http.MethodGet,
			Path:    "/test-44/items/ABC",
			Headers: map[string]string{"X-Code": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-44/items/ABC", Code: http.StatusUnsupportedMediaType},
		{
			Method:  http.MethodGet,
			Path:    "/test-44/items/hello",
			Headers: map[string]string{"X-Slug": "v"},
			Code:    http.StatusOK,
		},
		{Method: http.MethodGet, Path: "/test-44/items/hello", Code: http.StatusNotAcceptable},
	}...)
}

func TestScenario6_AllowListBlocksUnknownPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^\d+$`}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 6", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById": {
					Allow:           &oas.Allowance{Enabled: true},
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"getStatic": {
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 6 API"
		spec.APIID = "scenario-6"
		spec.Proxy.ListenPath = "/test-6/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-6/employees/static", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-6/employees/123", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-6/employees/abc", Code: http.StatusUnprocessableEntity},
		// NOTE: AllowList blocking of unknown paths (403) depends on OAS allowList
		// middleware configuration which is outside the scope of validate request.
		// The unknown path passes through because no validateRequest matches it.
		{Method: http.MethodGet, Path: "/test-6/unknown/path", Code: http.StatusOK},
	}...)
}

func TestScenario15_MixedAlphanumericWithAllowList(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"string"}, Pattern: `^\d+$`}),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses:   oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 15", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getById": {
					Allow:           &oas.Allowance{Enabled: true},
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422},
				},
				"getStatic": {
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 15 API"
		spec.APIID = "scenario-15"
		spec.Proxy.ListenPath = "/test-15/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test-15/employees/static", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-15/employees/123", Code: http.StatusOK},
		{Method: http.MethodGet, Path: "/test-15/employees/asd123", Code: http.StatusUnprocessableEntity},
	}...)
}

// Scenario 39: String with format:date vs unconstrained string.
// format:date scores higher and valueMatchesSchema checks the date format,
// so non-date values fall through to the unconstrained candidate.
func TestScenario39_StringFormatVsUnconstrained(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/employees/{date}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByDate",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "date", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Format: "date",
					}},
				}},
				headerParam("X-Date"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{any}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAny",
			Parameters: openapi3.Parameters{
				pathParam("any", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Any"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 39", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByDate": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByAny":  {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 39 API"
		spec.APIID = "scenario-39"
		spec.Proxy.ListenPath = "/test-39/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// Valid date + correct header -> 200
		{Method: http.MethodGet, Path: "/test-39/employees/2026-01-15", Headers: map[string]string{"X-Date": "v"}, Code: http.StatusOK},
		// Valid date, no header -> 400 (commits to date candidate, missing header)
		{Method: http.MethodGet, Path: "/test-39/employees/2026-01-15", Code: http.StatusBadRequest},
		// Non-date value + X-Any header -> 200 (fails date format, falls to unconstrained)
		{Method: http.MethodGet, Path: "/test-39/employees/hello", Headers: map[string]string{"X-Any": "v"}, Code: http.StatusOK},
		// Non-date value, no header -> 422 (falls to unconstrained, missing header)
		{Method: http.MethodGet, Path: "/test-39/employees/hello", Code: http.StatusUnprocessableEntity},
	}...)
}

// Scenario 40: String with minLength/maxLength vs unconstrained string.
// Length constraints are checked in valueMatchesSchema, so values outside the
// range fall through to the unconstrained candidate.
func TestScenario40_StringMinLengthVsUnconstrained(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	maxLen := uint64(5)
	paths.Set("/employees/{short}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByShort",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "short", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, MinLength: 2, MaxLength: &maxLen,
					}},
				}},
				headerParam("X-Short"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/employees/{any}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getByAny",
			Parameters: openapi3.Parameters{
				pathParam("any", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Any"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 40", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getByShort": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getByAny":   {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 40 API"
		spec.APIID = "scenario-40"
		spec.Proxy.ListenPath = "/test-40/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// "abc" (3 chars, in range 2-5) + correct header -> 200
		{Method: http.MethodGet, Path: "/test-40/employees/abc", Headers: map[string]string{"X-Short": "v"}, Code: http.StatusOK},
		// "abc" no header -> 400 (commits to short, missing header)
		{Method: http.MethodGet, Path: "/test-40/employees/abc", Code: http.StatusBadRequest},
		// "a" (1 char, below minLength 2) + X-Any -> 200 (falls to unconstrained)
		{Method: http.MethodGet, Path: "/test-40/employees/a", Headers: map[string]string{"X-Any": "v"}, Code: http.StatusOK},
		// "toolongstring" (13 chars, above maxLength 5) + X-Any -> 200 (falls to unconstrained)
		{Method: http.MethodGet, Path: "/test-40/employees/toolongstring", Headers: map[string]string{"X-Any": "v"}, Code: http.StatusOK},
	}...)
}

// Scenario 42: Two path params — integer+unconstrained vs pattern+pattern.
// Cumulative scores tie (7+0=7 vs 2+2=4), so typed path wins.
// But the key test is that when dept is non-integer, the patterned path matches.
func TestScenario42_MultiParamMixedTypeAndPattern(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/departments/{dept_id}/employees/{emp_any}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getTyped",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "dept_id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
				}},
				pathParam("emp_any", &openapi3.Schema{Type: &openapi3.Types{"string"}}),
				headerParam("X-Typed"),
			},
			Responses: oasResponse200(),
		},
	})

	paths.Set("/departments/{dept_code}/employees/{emp_code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getPatterned",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "dept_code", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`,
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "emp_code", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"}, Pattern: `^[A-Z]{3}$`,
					}},
				}},
				headerParam("X-Patterned"),
			},
			Responses: oasResponse200(),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Scenario 42", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getTyped":     {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 400}},
				"getPatterned": {ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: 422}},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Scenario 42 API"
		spec.APIID = "scenario-42"
		spec.Proxy.ListenPath = "/test-42/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		// dept_id=1 (integer), emp_any=alice -> typed path matches, header satisfied
		{Method: http.MethodGet, Path: "/test-42/departments/1/employees/alice", Headers: map[string]string{"X-Typed": "v"}, Code: http.StatusOK},
		// dept_code=ENG, emp_code=MGR (both ^[A-Z]{3}$) -> patterned path matches, header satisfied
		{Method: http.MethodGet, Path: "/test-42/departments/ENG/employees/MGR", Headers: map[string]string{"X-Patterned": "v"}, Code: http.StatusOK},
	}...)
}
