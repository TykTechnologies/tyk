package gateway

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// TestOASPathCompilation verifies that OAS paths are correctly compiled into RxPaths
func TestOASPathCompilation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS with mock response
	paths := openapi3.NewPaths()
	paths.Set("/users", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getusers",
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
				"getusers": {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    200,
						Body:    `{"message": "mocked"}`,
					},
				},
			},
		},
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "OAS Path Compilation Test"
		spec.APIID = "oas-path-test"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	// Check that the API was loaded
	assert.NotNil(t, api)
	assert.True(t, api.IsOAS)

	// Check that RxPaths contains entries
	assert.NotEmpty(t, api.RxPaths, "RxPaths should not be empty")

	// Get the default version paths
	var versionName string
	for name := range api.RxPaths {
		versionName = name
		break
	}

	urlSpecs := api.RxPaths[versionName]
	t.Logf("Found %d path specs for version %s", len(urlSpecs), versionName)

	// Check if any of them are OAS mock response paths
	foundOASMock := false
	for i, urlSpec := range urlSpecs {
		t.Logf("Path %d: Status=%v, OASMethod=%s, OASPath=%s",
			i, urlSpec.Status, urlSpec.OASMethod, urlSpec.OASPath)

		if urlSpec.Status == OASMockResponse {
			foundOASMock = true
			t.Logf("Found OAS mock response path: %s %s", urlSpec.OASMethod, urlSpec.OASPath)
			assert.NotNil(t, urlSpec.OASMockResponseMeta, "OAS mock response meta should not be nil")
			assert.True(t, urlSpec.OASMockResponseMeta.Enabled, "Mock response should be enabled")
		}
	}

	assert.True(t, foundOASMock, "Should have found at least one OAS mock response path")

	// Additional check: verify hasActiveMock returns true
	assert.True(t, api.hasActiveMock(), "API should have active mock")

	ts.Gw.LoadAPI()
}

func ptrStr(s string) *string {
	return &s
}
