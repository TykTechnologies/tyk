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
// for both base and child versions of Tyk OAS APIs with the unified path matching
func TestOASMockResponseVersioning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base OAS definition
	baseOAS := oas.OAS{}
	baseOAS.T = baseOASDoc(t)

	// Set up mock response for base version
	baseOAS.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getendpoint": {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    200,
						Body:    `{"version": "base"}`,
						Headers: []oas.Header{
							{Name: "Content-Type", Value: "application/json"},
						},
					},
				},
			},
		},
	})

	// Create child OAS definition with different mock response
	childOAS := oas.OAS{}
	childOAS.T = baseOASDoc(t)
	childOAS.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getendpoint": {
					MockResponse: &oas.MockResponse{
						Enabled: true,
						Code:    200,
						Body:    `{"version": "child1"}`,
						Headers: []oas.Header{
							{Name: "Content-Type", Value: "application/json"},
						},
					},
				},
			},
		},
	})

	// Extract to Classic format for versioning setup
	var baseAPIDefinition apidef.APIDefinition
	baseOAS.ExtractTo(&baseAPIDefinition)

	var childAPIDefinition apidef.APIDefinition
	childOAS.ExtractTo(&childAPIDefinition)

	t.Run("Test Case 1: Base Version Mock Response", func(t *testing.T) {
		// Create API with base version
		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Base Version Test"
			spec.APIID = "oas-mock-base"
			spec.Proxy.ListenPath = "/test/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = baseOAS

			// Configure versioning - v1 is NOT default
			spec.VersionData = apidef.VersionData{
				NotVersioned: false,
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name: "v1",
					},
				},
			}
			spec.VersionDefinition = apidef.VersionDefinition{
				Location: "header",
				Key:      "X-API-Version",
			}
		})[0]

		// Test base version with explicit version header
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/endpoint",
				Code:    http.StatusOK,
				Headers: map[string]string{"X-API-Version": "v1"},
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					matches := response["version"] == "base"
					if !matches {
						t.Logf("Expected version 'base', got '%s'", response["version"])
					}
					return matches
				},
			},
		}...)

		// Cleanup
		ts.Gw.LoadAPI()
		_ = api
	})

	t.Run("Test Case 2: Child Version Mock Response (Default)", func(t *testing.T) {
		// Create API with base and child versions
		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Child Version Test"
			spec.APIID = "oas-mock-child"
			spec.Proxy.ListenPath = "/test/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = childOAS

			// Configure versioning with v2 as default
			spec.VersionData = apidef.VersionData{
				NotVersioned:   false,
				DefaultVersion: "v2",
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name:             "v1",
						UseExtendedPaths: true,
						ExtendedPaths:    baseAPIDefinition.VersionData.Versions["Default"].ExtendedPaths,
					},
					"v2": {
						Name:             "v2",
						UseExtendedPaths: true,
						ExtendedPaths:    childAPIDefinition.VersionData.Versions["Default"].ExtendedPaths,
					},
				},
			}
			spec.VersionDefinition = apidef.VersionDefinition{
				Location: "header",
				Key:      "X-API-Version",
				Default:  "v2",
			}
		})[0]

		// Test child version without version header (should use default v2)
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/test/endpoint",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					matches := response["version"] == "child1"
					if !matches {
						t.Logf("Expected version 'child1', got '%s'", response["version"])
					}
					return matches
				},
			},
		}...)

		// Cleanup
		ts.Gw.LoadAPI()
		_ = api
	})

	t.Run("Test Case 3: Explicit Child Version Selection", func(t *testing.T) {
		// Create API with base and child versions
		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Explicit Child Version Test"
			spec.APIID = "oas-mock-explicit"
			spec.Proxy.ListenPath = "/test/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = childOAS

			// Configure versioning with v1 as default
			spec.VersionData = apidef.VersionData{
				NotVersioned:   false,
				DefaultVersion: "v1",
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name:             "v1",
						UseExtendedPaths: true,
						ExtendedPaths:    baseAPIDefinition.VersionData.Versions["Default"].ExtendedPaths,
					},
					"v2": {
						Name:             "v2",
						UseExtendedPaths: true,
						ExtendedPaths:    childAPIDefinition.VersionData.Versions["Default"].ExtendedPaths,
					},
				},
			}
			spec.VersionDefinition = apidef.VersionDefinition{
				Location: "header",
				Key:      "X-API-Version",
				Default:  "v1",
			}
		})[0]

		// Test with explicit v1 header (base version)
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/endpoint",
				Code:    http.StatusOK,
				Headers: map[string]string{"X-API-Version": "v1"},
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					matches := response["version"] == "base"
					if !matches {
						t.Logf("Expected version 'base', got '%s'", response["version"])
					}
					return matches
				},
			},
		}...)

		// Test with explicit v2 header (child version)
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/endpoint",
				Code:    http.StatusOK,
				Headers: map[string]string{"X-API-Version": "v2"},
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]string
					if err := json.Unmarshal(bytes, &response); err != nil {
						t.Logf("Failed to unmarshal response: %v", err)
						return false
					}
					matches := response["version"] == "child1"
					if !matches {
						t.Logf("Expected version 'child1', got '%s'", response["version"])
					}
					return matches
				},
			},
		}...)

		// Cleanup
		ts.Gw.LoadAPI()
		_ = api
	})

	t.Run("Test Case 4: Multiple Versions with Different Endpoints", func(t *testing.T) {
		// Create OAS with multiple endpoints
		multiEndpointOAS := oas.OAS{}
		multiEndpointOAS.T = multiEndpointOASDoc(t)

		// Base version has endpoint1 mocked
		multiEndpointOAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getendpoint1": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"endpoint": "endpoint1", "version": "v1"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		var v1Definition apidef.APIDefinition
		multiEndpointOAS.ExtractTo(&v1Definition)

		// Child version has endpoint2 mocked
		childMultiOAS := oas.OAS{}
		childMultiOAS.T = multiEndpointOASDoc(t)
		childMultiOAS.SetTykExtension(&oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: oas.Operations{
					"getendpoint2": {
						MockResponse: &oas.MockResponse{
							Enabled: true,
							Code:    200,
							Body:    `{"endpoint": "endpoint2", "version": "v2"}`,
							Headers: []oas.Header{
								{Name: "Content-Type", Value: "application/json"},
							},
						},
					},
				},
			},
		})

		var v2Definition apidef.APIDefinition
		childMultiOAS.ExtractTo(&v2Definition)

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Name = "OAS Mock Response Multiple Endpoints Test"
			spec.APIID = "oas-mock-multi"
			spec.Proxy.ListenPath = "/test/"
			spec.UseKeylessAccess = true
			spec.IsOAS = true
			spec.OAS = childMultiOAS

			// Configure versioning
			spec.VersionData = apidef.VersionData{
				NotVersioned:   false,
				DefaultVersion: "v2",
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name:             "v1",
						UseExtendedPaths: true,
						ExtendedPaths:    v1Definition.VersionData.Versions["Default"].ExtendedPaths,
					},
					"v2": {
						Name:             "v2",
						UseExtendedPaths: true,
						ExtendedPaths:    v2Definition.VersionData.Versions["Default"].ExtendedPaths,
					},
				},
			}
			spec.VersionDefinition = apidef.VersionDefinition{
				Location: "header",
				Key:      "X-API-Version",
				Default:  "v2",
			}
		})[0]

		// Test v1 endpoint1 is mocked
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:  http.MethodGet,
				Path:    "/test/endpoint1",
				Code:    http.StatusOK,
				Headers: map[string]string{"X-API-Version": "v1"},
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]interface{}
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["endpoint"] == "endpoint1" && response["version"] == "v1"
				},
			},
		}...)

		// Test v2 endpoint2 is mocked (default version)
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method: http.MethodGet,
				Path:   "/test/endpoint2",
				Code:   http.StatusOK,
				BodyMatchFunc: func(bytes []byte) bool {
					var response map[string]interface{}
					if err := json.Unmarshal(bytes, &response); err != nil {
						return false
					}
					return response["endpoint"] == "endpoint2" && response["version"] == "v2"
				},
			},
		}...)

		// Cleanup
		ts.Gw.LoadAPI()
		_ = api
	})
}

// baseOASDoc returns a simple OAS document for testing
func baseOASDoc(t *testing.T) openapi3.T {
	t.Helper()

	paths := openapi3.NewPaths()
	paths.Set("/endpoint", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getendpoint",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtr("Success"),
						Content: openapi3.Content{
							"application/json": &openapi3.MediaType{
								Schema: &openapi3.SchemaRef{
									Value: &openapi3.Schema{
										Type: &openapi3.Types{"object"},
									},
								},
							},
						},
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

	return doc
}

// multiEndpointOASDoc returns an OAS document with multiple endpoints
func multiEndpointOASDoc(t *testing.T) openapi3.T {
	t.Helper()

	paths := openapi3.NewPaths()
	paths.Set("/endpoint1", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getendpoint1",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtr("Success"),
					},
				}),
			),
		},
	})
	paths.Set("/endpoint2", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getendpoint2",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtr("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   "Mock Response Multiple Endpoints Test API",
			Version: "1.0.0",
		},
		Paths: paths,
	}

	return doc
}

func stringPtr(s string) *string {
	return &s
}
