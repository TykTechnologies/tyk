package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestOASMockResponseVersioning tests that mock responses work correctly
// with OAS API versioning. In Tyk's OAS versioning model, each version is
// a separate API definition with its own OAS spec and listen path.
// The base API references child versions by ID.
func TestOASMockResponseVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Separate versioned APIs with different mock responses", func(t *testing.T) {
		// Create v1 (base) OAS definition
		v1OAS := oas.OAS{}
		v1OAS.T = createOASDoc(t, "v1 API", "/anything")
		v1OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "v1 API",
				Versioning: &oas.Versioning{
					Enabled:           true,
					Name:              "v1",
					Default:           "self",
					Location:          "header",
					Key:               "x-api-version",
					FallbackToDefault: true,
					Versions: []oas.VersionToID{
						{Name: "v2", ID: "v2-api-id"},
					},
				},
			},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getanything": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"version": "v1", "message": "response from v1"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		// Create v2 OAS definition (separate API)
		v2OAS := oas.OAS{}
		v2OAS.T = createOASDoc(t, "v2 API", "/anything")
		v2OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "v2 API",
			},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getanything": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"version": "v2", "message": "response from v2"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		// Load both APIs - each version is a separate API
		ts.Gw.BuildAndLoadAPI(
			// v1 (base) API
			func(spec *APISpec) {
				spec.Name = "v1 API"
				spec.APIID = "v1-api-id"
				spec.Proxy.ListenPath = "/api/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v1OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v1"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v1": {Name: "v1", UseExtendedPaths: true},
				}
			},
			// v2 API (separate API definition)
			func(spec *APISpec) {
				spec.Name = "v2 API"
				spec.APIID = "v2-api-id"
				spec.Proxy.ListenPath = "/api-v2/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v2OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v2"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v2": {Name: "v2", UseExtendedPaths: true},
				}
			},
		)

		// Test v1 API returns v1 mock response
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/api/anything",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					if response["version"] != "v1" {
						t.Logf("Expected version 'v1', got '%s'", response["version"])
						return false
					}
					return true
				},
			},
		}...)

		// Test v2 API returns v2 mock response
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/api-v2/anything",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					if response["version"] != "v2" {
						t.Logf("Expected version 'v2', got '%s'", response["version"])
						return false
					}
					return true
				},
			},
		}...)
	})

	t.Run("Versioned APIs with URL versioning pattern", func(t *testing.T) {
		// This simulates the pattern where:
		// - /andrei/v1/anything -> v1 API
		// - /andrei/v2/anything -> v2 API (via URL versioning)

		// Create v1 (base) OAS definition with URL versioning
		v1OAS := oas.OAS{}
		v1OAS.T = createOASDoc(t, "Base API v1", "/endpoint")
		v1OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "Base API",
				Versioning: &oas.Versioning{
					Enabled:           true,
					Name:              "v1",
					Default:           "self",
					Location:          "url",
					Key:               "",
					FallbackToDefault: true,
					Versions: []oas.VersionToID{
						{Name: "v2", ID: "base-api-v2"},
					},
				},
			},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getendpoint": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"api": "base", "version": "v1"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		// Create v2 OAS definition
		v2OAS := oas.OAS{}
		v2OAS.T = createOASDoc(t, "Base API v2", "/endpoint")
		v2OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "Base API v2",
			},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getendpoint": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"api": "base", "version": "v2"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		// Load both APIs
		ts.Gw.BuildAndLoadAPI(
			// v1 (base) API - /base/v1/
			func(spec *APISpec) {
				spec.Name = "Base API v1"
				spec.APIID = "base-api-v1"
				spec.Proxy.ListenPath = "/base/v1/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v1OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v1"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v1": {Name: "v1", UseExtendedPaths: true},
				}
			},
			// v2 API - /base/v2/
			func(spec *APISpec) {
				spec.Name = "Base API v2"
				spec.APIID = "base-api-v2"
				spec.Proxy.ListenPath = "/base/v2/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v2OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v2"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v2": {Name: "v2", UseExtendedPaths: true},
				}
			},
		)

		// Test v1 API
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/base/v1/endpoint",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["version"] == "v1"
				},
			},
		}...)

		// Test v2 API
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/base/v2/endpoint",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["version"] == "v2"
				},
			},
		}...)
	})

	t.Run("Different middleware per version", func(t *testing.T) {
		// v1 has mock response enabled
		v1OAS := oas.OAS{}
		v1OAS.T = createOASDoc(t, "Middleware Test v1", "/test")
		v1OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{Name: "Middleware Test v1"},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"gettest": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"mocked": true}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		// v2 has mock response disabled (will proxy to upstream)
		v2OAS := oas.OAS{}
		v2OAS.T = createOASDoc(t, "Middleware Test v2", "/test")
		v2OAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{Name: "Middleware Test v2"},
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"gettest": {
						MockResponse: &oas.MockResponse{
							Enabled: false, // Disabled - will proxy to upstream
						},
					},
				},
			},
		})

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Name = "Middleware Test v1"
				spec.APIID = "mw-test-v1"
				spec.Proxy.ListenPath = "/mw-v1/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v1OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v1"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v1": {Name: "v1", UseExtendedPaths: true},
				}
			},
			func(spec *APISpec) {
				spec.Name = "Middleware Test v2"
				spec.APIID = "mw-test-v2"
				spec.Proxy.ListenPath = "/mw-v2/"
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = v2OAS
				spec.VersionData.NotVersioned = false
				spec.VersionData.DefaultVersion = "v2"
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v2": {Name: "v2", UseExtendedPaths: true},
				}
			},
		)

		// v1 returns mock response
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/mw-v1/test",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]bool
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal: %v, body: %s", err, string(bytes))
						return false
					}
					return response["mocked"] == true
				},
			},
		}...)

		// v2 proxies to upstream (mock disabled) - will get upstream response
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/mw-v2/test",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					// Should NOT be the mock response
					var response map[string]bool
					if err := json.Unmarshal(bytes, &response); err != nil {
						// Not JSON or different structure - that's expected from upstream
						return true
					}
					// If it parsed as our mock structure, it should NOT have mocked=true
					return response["mocked"] != true
				},
			},
		}...)
	})
}

// createOASDoc creates a simple OAS document for testing
func createOASDoc(t *testing.T, title, path string) openapi3.T {
	t.Helper()

	// Generate operationId from path (remove leading slash, add "get" prefix)
	operationID := "get" + path[1:]

	paths := openapi3.NewPaths()
	paths.Set(path, &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: operationID,
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtr("Success"),
					},
				}),
			),
		},
	})

	return openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   title,
			Version: "1.0.0",
		},
		Paths: paths,
	}
}

func stringPtr(s string) *string {
	return &s
}
