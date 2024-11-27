//go:build ee || dev

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/test"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestStreamShadowMiddlewareWithAPI(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})
	defer ts.Close()

	// Create an HTTP test server with an empty handler and a WaitGroup
	var wg sync.WaitGroup
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Webhook received!")
		defer wg.Done()
	}))
	defer testServer.Close()

	// Create API definition with stream shadow middleware enabled for specific path
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-api"
		spec.Name = "Test API"
		spec.Proxy.ListenPath = "/test-api/"
		spec.UseKeylessAccess = true

		spec.IsOAS = true
		spec.OAS = oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   "Shadow API",
					Version: "1.0.0",
				},
				Paths: openapi3.Paths{
					"/test": {
						Post: &openapi3.Operation{
							OperationID: "test",
							Responses:   openapi3.NewResponses(),
						},
					},
				},
			},
		}

		spec.OAS.Fill(*spec.APIDefinition)

		xTykAPIGateway := oas.XTykAPIGateway{
			Middleware: &oas.Middleware{
				Operations: map[string]*oas.Operation{
					"test": {
						StreamShadow: &oas.StreamShadow{
							Enabled:        true,
							StreamID:       "test-stream",
							StreamingApiId: "shadow-api",
						},
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
			},
		}

		spec.OAS.SetTykExtension(&xTykAPIGateway)
	}, func(spec *APISpec) {
		spec.APIID = "shadow-api"
		spec.Name = "Shadow API"
		spec.Proxy.ListenPath = "/shadow-api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   "Shadow API",
					Version: "1.0.0",
				},
				Paths: make(openapi3.Paths),
			},
		}

		spec.OAS.Extensions = map[string]interface{}{
			streams.ExtensionTykStreaming: map[string]interface{}{
				"streams": map[string]interface{}{
					"test-stream": map[string]interface{}{
						"input": map[string]interface{}{
							"stream_shadow": map[string]interface{}{},
						},
						"output": map[string]interface{}{
							"http_client": map[string]interface{}{
								"url": testServer.URL,
							},
						},
					},
				},
			},
		}

		spec.OAS.Fill(*spec.APIDefinition)
	})

	t.Run("should shadow request and response payloads", func(t *testing.T) {
		// Test request with JSON payload
		reqBody := map[string]interface{}{
			"test": "request",
		}
		reqBodyBytes, _ := json.Marshal(reqBody)
		wg.Add(1)

		// Make request to main API
		_, _ = ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodPost,
				Path:      "/test-api/test",
				Data:      string(reqBodyBytes),
				Headers:   map[string]string{"Content-Type": "application/json"},
				Code:      http.StatusOK,
				BodyMatch: `/test-api/test`,
			},
		}...)

		wg.Wait()
	})
}
