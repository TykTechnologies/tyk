package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

func TestMockResponse_OverlappingParameterisedPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	// /items/{code} — pattern ^[a-z]+$, returns "alpha-mock"
	paths.Set("/items/{code}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getItemByCode",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "code", In: "path", Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Pattern: "^[a-z]+$",
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

	// /items/{num} — type integer, returns "numeric-mock"
	paths.Set("/items/{num}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getItemByNum",
			Parameters: openapi3.Parameters{
				{Value: &openapi3.Parameter{
					Name: "num", In: "path", Required: true,
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

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Mock Overlapping Test", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getItemByCode": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: "alpha-mock"},
				},
				"getItemByNum": {
					MockResponse: &oas.MockResponse{Enabled: true, Code: 200, Body: "numeric-mock"},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Mock Overlapping API"
		spec.APIID = "mock-overlap"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	_, _ = ts.Run(t, []test.TestCase{
		{
			// /items/abc → matches {code} pattern ^[a-z]+$ → "alpha-mock"
			Method:    http.MethodGet,
			Path:      "/api/items/abc",
			Code:      http.StatusOK,
			BodyMatch: "alpha-mock",
		},
		{
			// /items/123 → matches {num} type integer → "numeric-mock"
			Method:    http.MethodGet,
			Path:      "/api/items/123",
			Code:      http.StatusOK,
			BodyMatch: "numeric-mock",
		},
	}...)
}
