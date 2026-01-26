package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestOASPathMatchingRespectGatewayConfig verifies that OAS APIs respect gateway-level
// path matching configurations like EnablePathPrefixMatching.
// This test should FAIL before the unified path matching fix and PASS after.
func TestOASPathMatchingRespectGatewayConfig(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS API with mock response on /users
	paths := openapi3.NewPaths()
	paths.Set("/users", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getusers",
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
		Info: &openapi3.Info{
			Title:   "Path Matching Test API",
			Version: "1.0.0",
		},
		Paths: paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getusers": {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    200,
						Body:    `{"message": "prefix matching works"}`,
						Headers: []oas.Header{
							{Name: "Content-Type", Value: "application/json"},
						},
					},
				},
			},
		},
	})

	// Enable prefix matching at gateway level
	conf := ts.Gw.GetConfig()
	originalPrefixMatch := conf.HttpServerOptions.EnablePathPrefixMatching
	conf.HttpServerOptions.EnablePathPrefixMatching = true
	ts.Gw.SetConfig(conf)
	defer func() {
		conf.HttpServerOptions.EnablePathPrefixMatching = originalPrefixMatch
		ts.Gw.SetConfig(conf)
	}()

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "OAS Prefix Matching Test"
		spec.APIID = "oas-prefix-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	// WITHOUT the fix: This request to /api/users/123 will NOT match /users
	// because the OAS middleware uses findOperation which doesn't respect EnablePathPrefixMatching

	// WITH the fix: This request WILL match because we use the standard regex-based
	// path matching which respects EnablePathPrefixMatching

	// Test that /api/users/123 matches /users when prefix matching is enabled
	_, _ = ts.Run(t, []test.TestCase{
		{
			Method: http.MethodGet,
			Path:   "/api/users/123",
			Code:   http.StatusOK,
			BodyMatchFunc: func(bytes []byte) bool {
				var response map[string]string
				if err := json.Unmarshal(bytes, &response); err != nil {
					t.Logf("Failed to unmarshal response: %v, body: %s", err, string(bytes))
					return false
				}
				matches := response["message"] == "prefix matching works"
				if !matches {
					t.Logf("Expected mock response, got: %s", string(bytes))
				}
				return matches
			},
		},
	}...)

	ts.Gw.LoadAPI()
	_ = api
}

func stringPtrHelper(s string) *string {
	return &s
}
