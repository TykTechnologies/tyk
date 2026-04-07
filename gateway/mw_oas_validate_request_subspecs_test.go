package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestValidateRequest_SingleParameterisedPath ensures that a single parameterised path
// with a sub-spec still works correctly (no regression from two-step matching).
func TestValidateRequest_SingleParameterisedPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-zA-Z]+$",
					}},
				}},
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
		Info:    &openapi3.Info{Title: "Single Param Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Single Param API"
		spec.APIID = "single-param"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Valid path param → passes validation
			Method: http.MethodGet,
			Path:   "/api/users/john",
			Code:   http.StatusOK,
		},
		{
			// Invalid path param → fails validation (123 doesn't match ^[a-zA-Z]+$)
			Method: http.MethodGet,
			Path:   "/api/users/123",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestValidateRequest_OverlappingParameterisedPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Two paths that compile to the same generic regex /employees/([^/]+)
	// but have different path parameter schemas and different required headers.
	paths := openapi3.NewPaths()

	// /employees/{prct} — pattern ^[a-z]$, requires header "def"
	paths.Set("/employees/{prct}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByPrct",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "prct", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z]$",
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "def", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	// /employees/{zd} — type number, pattern [1-9], requires header "abc"
	paths.Set("/employees/{zd}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByZd",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "zd", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"number"},
						Pattern: "[1-9]",
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "abc", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
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
		Info:    &openapi3.Info{Title: "Overlapping Params Test", Version: "1.0.0"},
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
		spec.Name = "Overlapping Params API"
		spec.APIID = "overlapping-params"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// /employees/a matches {prct} pattern ^[a-z]$ → requires header "def"
			// Missing header "def" → 422
			Method:    http.MethodGet,
			Path:      "/api/employees/a",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: "def",
		},
		{
			// /employees/a with header "def" → 200
			Method:  http.MethodGet,
			Path:    "/api/employees/a",
			Code:    http.StatusOK,
			Headers: map[string]string{"def": "value"},
		},
		{
			// /employees/1 matches {zd} pattern [1-9] → requires header "abc"
			// Missing header "abc" → 422
			Method:    http.MethodGet,
			Path:      "/api/employees/1",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: "abc",
		},
		{
			// /employees/1 with header "abc" → 200
			Method:  http.MethodGet,
			Path:    "/api/employees/1",
			Code:    http.StatusOK,
			Headers: map[string]string{"abc": "value"},
		},
		{
			// /employees/ddd111 matches neither sub-spec → fallback → rejected
			Method: http.MethodGet,
			Path:   "/api/employees/ddd111",
			Code:   http.StatusUnprocessableEntity,
		},
	}...)
}

func TestValidateRequest_OverlappingMultiSegmentPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	// /dept/{deptId}/employees/{empId} — deptId: integer, empId: integer
	paths.Set("/dept/{deptId}/employees/{empId}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "deptId", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"integer"},
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "empId", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"integer"},
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "X-Emp-Id-Header", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	// /dept/{deptId}/employees/{name} — deptId: integer, name: string with pattern ^[a-z]+$
	paths.Set("/dept/{deptId}/employees/{name}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getEmployeeByName",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "deptId", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"integer"},
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "name", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z]+$",
					}},
				}},
				{Value: &openapi3.Parameter{
					Name: "X-Name-Header", In: "header", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"string"},
					}},
				}},
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
		Info:    &openapi3.Info{Title: "Multi-Segment Overlapping Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getEmployeeById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
				"getEmployeeByName": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Multi-Segment Overlapping API"
		spec.APIID = "multi-segment-overlap"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// /dept/1/employees/42 → matches empId (integer) → requires X-Emp-Id-Header
			Method:    http.MethodGet,
			Path:      "/api/dept/1/employees/42",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: "X-Emp-Id-Header",
		},
		{
			// /dept/1/employees/42 with correct header → 200
			Method:  http.MethodGet,
			Path:    "/api/dept/1/employees/42",
			Code:    http.StatusOK,
			Headers: map[string]string{"X-Emp-Id-Header": "val"},
		},
		{
			// /dept/1/employees/john → matches name (^[a-z]+$) → requires X-Name-Header
			Method:    http.MethodGet,
			Path:      "/api/dept/1/employees/john",
			Code:      http.StatusUnprocessableEntity,
			BodyMatch: "X-Name-Header",
		},
		{
			// /dept/1/employees/john with correct header → 200
			Method:  http.MethodGet,
			Path:    "/api/dept/1/employees/john",
			Code:    http.StatusOK,
			Headers: map[string]string{"X-Name-Header": "val"},
		},
	}...)
}

func TestValidateRequest_OverlappingWithStaticPath(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Three paths: static + two overlapping parameterised
	paths := openapi3.NewPaths()

	paths.Set("/employees/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAdmin",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "id", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type: &openapi3.Types{"integer"},
					}},
				}},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: stringPtrHelper("Success")},
				}),
			),
		},
	})

	paths.Set("/employees/{slug}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getBySlug",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "slug", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z-]+$",
					}},
				}},
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
		Info:    &openapi3.Info{Title: "Static + Overlapping Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getAdmin": {},
				"getById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
				"getBySlug": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Static Plus Overlapping API"
		spec.APIID = "static-plus-overlap"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// Static path /employees/admin — no validateRequest → 200
			Method: http.MethodGet,
			Path:   "/api/employees/admin",
			Code:   http.StatusOK,
		},
		{
			// /employees/123 → matches integer {id} → 200 (validates ok)
			Method: http.MethodGet,
			Path:   "/api/employees/123",
			Code:   http.StatusOK,
		},
		{
			// /employees/john-doe → matches ^[a-z-]+$ {slug} → 200
			Method: http.MethodGet,
			Path:   "/api/employees/john-doe",
			Code:   http.StatusOK,
		},
	}...)
}
