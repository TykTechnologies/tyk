package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestMockResponse_overlappingRegexEndpoints covers two endpoints that sit at the
// same position in the URL and are told apart only by their regex, the shape a
// Classic-to-OAS migration produces.
//
// Mock responses compile their matcher from the OAS path key, so both endpoints
// used to become ^/users/([^/]+)$ and collapse into one: whichever sorted first
// answered every request, and /users/123 was served the letters endpoint's body.
// The matcher is now built from the regex each placeholder stands for, so the two
// stay distinct.
func TestMockResponse_overlappingRegexEndpoints(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	emptyDescription := ""

	responses := func() *openapi3.Responses {
		r := openapi3.NewResponses()
		r.Delete("default")
		r.Set("200", &openapi3.ResponseRef{Value: &openapi3.Response{Description: &emptyDescription}})

		return r
	}

	// Migration writes path parameters on the path item rather than the operation.
	pathParam := func(name, pattern string) openapi3.Parameters {
		return openapi3.Parameters{{Value: &openapi3.Parameter{
			Name: name, In: "path", Required: true,
			Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern(pattern)},
		}}}
	}

	paths := openapi3.NewPaths()
	paths.Set("/users/{customRegex1}", &openapi3.PathItem{
		Get:        &openapi3.Operation{OperationID: "users/[a-z]+GET", Responses: responses()},
		Parameters: pathParam("customRegex1", "[a-z]+"),
	})
	paths.Set("/users/{customRegex2}", &openapi3.PathItem{
		Get:        &openapi3.Operation{OperationID: "users/[0-9]+GET", Responses: responses()},
		Parameters: pathParam("customRegex2", "[0-9]+"),
	})

	mock := func(body string) *oas.Operation {
		return &oas.Operation{
			Allow:                &oas.Allowance{Enabled: true},
			IgnoreAuthentication: &oas.Allowance{Enabled: true},
			MockResponse: &oas.MockResponse{
				Enabled:         true,
				Code:            http.StatusOK,
				Body:            body,
				FromOASExamples: &oas.FromOASExamples{},
			},
		}
	}

	doc := oas.OAS{}
	doc.OpenAPI = "3.0.3"
	doc.Info = &openapi3.Info{Version: "1", Title: "overlapping regex endpoints"}
	doc.Paths = paths
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{Operations: oas.Operations{
			"users/[a-z]+GET": mock(`{"user_by_name":true}`),
			"users/[0-9]+GET": mock(`{"user_by_number":true}`),
		}},
	})

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/overlapping/"
		spec.Proxy.StripListenPath = true
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = doc
	})

	_, _ = g.Run(t,
		test.TestCase{Path: "/overlapping/users/gogo", BodyMatch: `user_by_name`, Code: http.StatusOK},
		test.TestCase{Path: "/overlapping/users/123", BodyMatch: `user_by_number`, Code: http.StatusOK},
	)
}
