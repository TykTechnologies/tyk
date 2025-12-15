package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestOASMockResponseUnifiedPathMatching verifies that the unified path matching
// implementation correctly applies gateway configuration options to OAS mock responses
func TestOASMockResponseUnifiedPathMatching(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Basic OAS Mock Response", func(t *testing.T) {
		// Create simple OAS with mock response
		oasAPI := createSimpleOASWithMock(t, `{"message": "mocked"}`)

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Basic Test"
			spec.APIID = "oas-mock-basic"
			spec.Proxy.ListenPath = "/api/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})[0]

		// Debug: Log the RxPaths and version configuration
		t.Logf("NotVersioned: %v, DefaultVersion: %s", api.VersionData.NotVersioned, api.VersionData.DefaultVersion)
		t.Logf("VersionDefinition.Enabled: %v", api.VersionDefinition.Enabled)
		t.Logf("RxPaths keys: %v", keysOf(api.RxPaths))
		for vName, urlSpecs := range api.RxPaths {
			t.Logf("Version '%s' has %d URLSpecs", vName, len(urlSpecs))
			for i, spec := range urlSpecs {
				if spec.Status == OASMockResponse {
					t.Logf("  [%d] OASMockResponse: %s %s", i, spec.OASMethod, spec.OASPath)
				}
			}
		}
		t.Logf("hasActiveMock: %v", api.hasActiveMock())

		// Verify mock response is returned
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/api/users",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal: %v", err)
						return false
					}
					return response["message"] == "mocked"
				},
			},
		}...)

		ts.Gw.LoadAPI()
		_ = api
	})

	t.Run("OAS Mock Response with StripListenPath", func(t *testing.T) {
		oasAPI := createSimpleOASWithMock(t, `{"message": "mocked with strip"}`)

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Strip Test"
			spec.APIID = "oas-mock-strip"
			spec.Proxy.ListenPath = "/api/"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})[0]

		// With StripListenPath, request /api/users should match OAS path /users
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/api/users",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["message"] == "mocked with strip"
				},
			},
		}...)

		ts.Gw.LoadAPI()
		_ = api
	})

	t.Run("OAS Mock Response Respects Gateway Config", func(t *testing.T) {
		// This test verifies that gateway-level path matching configurations
		// are respected for OAS APIs (which was the main issue being fixed)

		oasAPI := createSimpleOASWithMock(t, `{"message": "prefix matching works"}`)

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
			spec.Name = "OAS Mock Response Gateway Config Test"
			spec.APIID = "oas-mock-config"
			spec.Proxy.ListenPath = "/api/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = oasAPI
		})[0]

		// With prefix matching enabled, /api/users should match /api/users/123
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/api/users/123",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["message"] == "prefix matching works"
				},
			},
		}...)

		ts.Gw.LoadAPI()
		_ = api
	})
}

func createSimpleOASWithMock(t *testing.T, mockBody string) oas.OAS {
	t.Helper()

	paths := openapi3.NewPaths()
	paths.Set("/users", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getusers",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrString("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   "Mock Response Test API",
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
						Body:    mockBody,
						Headers: []oas.Header{
							{Name: "Content-Type", Value: "application/json"},
						},
					},
				},
			},
		},
	})

	return oasAPI
}

func ptrString(s string) *string {
	return &s
}

func keysOf(m map[string][]URLSpec) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
