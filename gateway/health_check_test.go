package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

func TestGateway_readinessHandler(t *testing.T) {
	tests := []struct {
		name                   string
		method                 string
		setupGateway           func(*Gateway)
		setupHealthCheck       func(*Gateway)
		expectedStatus         int
		expectedErrorMessage   string
		expectedResponseStatus HealthCheckStatus
	}{
		{
			name:                 "method not allowed - POST",
			method:               http.MethodPost,
			setupGateway:         func(_ *Gateway) {},
			setupHealthCheck:     func(_ *Gateway) {},
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedErrorMessage: "Method Not Allowed",
		},
		{
			name:                 "method not allowed - PUT",
			method:               http.MethodPut,
			setupGateway:         func(_ *Gateway) {},
			setupHealthCheck:     func(_ *Gateway) {},
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedErrorMessage: "Method Not Allowed",
		},
		{
			name:   "redis health check failed",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No need to mock storage connection handler for this test
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with failed redis
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:       http.StatusServiceUnavailable,
			expectedErrorMessage: "Redis connection not available",
		},
		{
			name:   "no APIs loaded with UseDBAppConfigs enabled",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable UseDBAppConfigs
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = true
				gw.SetConfig(conf)

				// Ensure no APIs are loaded
				gw.apisMu.Lock()
				gw.apiSpecs = []*APISpec{}
				gw.apisMu.Unlock()
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with passing redis
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:       http.StatusServiceUnavailable,
			expectedErrorMessage: "API definitions not loaded",
		},
		{
			name:   "no APIs loaded with UseDBAppConfigs disabled - should pass",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Disable UseDBAppConfigs
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = false
				gw.SetConfig(conf)

				// Ensure no APIs are loaded
				gw.apisMu.Lock()
				gw.apiSpecs = []*APISpec{}
				gw.apisMu.Unlock()
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with passing redis
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
		},
		{
			name:   "all checks pass",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable UseDBAppConfigs
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = true
				gw.SetConfig(conf)

				// Load some APIs
				gw.apisMu.Lock()
				gw.apiSpecs = []*APISpec{
					{APIDefinition: &apidef.APIDefinition{APIID: "test-api"}},
				}
				gw.apisMu.Unlock()
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with all passing
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Pass,
						ComponentType: System,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
		},
		{
			name:   "redis connected but health check shows warning - should pass",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Load some APIs
				gw.apisMu.Lock()
				gw.apiSpecs = []*APISpec{
					{APIDefinition: &apidef.APIDefinition{APIID: "test-api"}},
				}
				gw.apisMu.Unlock()
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with redis warning (not failure)
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Warn,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
		},
		{
			name:   "hide generator header enabled",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable HideGeneratorHeader
				conf := gw.GetConfig()
				conf.HideGeneratorHeader = true
				conf.UseDBAppConfigs = false
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with passing redis
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
		},
		{
			name:   "no redis health check data and storage not connected",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Create a real connection handler but don't connect it
				gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())
			},
			setupHealthCheck: func(gw *Gateway) {
				// No redis health check data
				gw.setCurrentHealthCheckInfo(map[string]HealthCheckItem{})
			},
			expectedStatus:       http.StatusServiceUnavailable,
			expectedErrorMessage: "Redis connection not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new gateway instance for each test
			gw := NewGateway(config.Config{}, nil)

			// Apply test-specific setup
			tt.setupGateway(gw)
			tt.setupHealthCheck(gw)

			// Create request
			req := httptest.NewRequest(tt.method, "/ready", nil)
			w := httptest.NewRecorder()

			// Call the handler
			gw.readinessHandler(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Check content type
			if w.Code != http.StatusMethodNotAllowed {
				assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			}

			// Check response body
			if tt.expectedStatus == http.StatusOK {
				var response HealthCheckResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Equal(t, tt.expectedResponseStatus, response.Status)
				assert.Equal(t, VERSION, response.Version)
				assert.Equal(t, "Tyk GW Ready", response.Description)
				assert.NotNil(t, response.Details)

				// Note: Mascot headers are not tested in unit tests due to sync.Once behavior
				// which makes them unreliable in test environments where multiple tests run
			} else if tt.expectedStatus == http.StatusServiceUnavailable {
				var errorResponse apiStatusMessage
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(t, err)

				assert.Equal(t, "error", errorResponse.Status)
				assert.Equal(t, tt.expectedErrorMessage, errorResponse.Message)
			} else if tt.expectedStatus == http.StatusMethodNotAllowed {
				var errorResponse apiStatusMessage
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(t, err)

				assert.Equal(t, "error", errorResponse.Status)
				assert.Equal(t, tt.expectedErrorMessage, errorResponse.Message)
			}
		})
	}
}

func TestGateway_readinessHandler_Integration(t *testing.T) {
	// Integration test using the actual test framework
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("readiness endpoint responds correctly", func(t *testing.T) {
		// Test with a working gateway - use the configured readiness endpoint name
		readinessPath := "/" + ts.Gw.GetConfig().ReadinessCheckEndpointName
		resp, err := http.Get(ts.URL + readinessPath)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var response HealthCheckResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, Pass, response.Status)
		assert.Equal(t, VERSION, response.Version)
		assert.Equal(t, "Tyk GW Ready", response.Description)
		// Details field has omitempty tag, so it may be nil when empty
		// This is expected behavior in test environment where health checks may not have run yet
	})

	t.Run("method not allowed", func(t *testing.T) {
		readinessPath := "/" + ts.Gw.GetConfig().ReadinessCheckEndpointName
		req, err := http.NewRequest(http.MethodPost, ts.URL+readinessPath, nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

		var errorResponse apiStatusMessage
		err = json.NewDecoder(resp.Body).Decode(&errorResponse)
		require.NoError(t, err)

		assert.Equal(t, "error", errorResponse.Status)
		assert.Equal(t, "Method Not Allowed", errorResponse.Message)
	})
}
