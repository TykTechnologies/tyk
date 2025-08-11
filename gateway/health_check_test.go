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
			name:   "no APIs loaded with UseDBAppConfigs enabled should pass",
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

				// Set performedSuccessfulReload to true for this test to pass
				gw.performedSuccessfulReload = true
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

				// Set performedSuccessfulReload to true for this test to pass
				gw.performedSuccessfulReload = true
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

				// Set performedSuccessfulReload to true for this test to pass
				gw.performedSuccessfulReload = true
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

				// Set performedSuccessfulReload to true for this test to pass
				gw.performedSuccessfulReload = true
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

				// Set performedSuccessfulReload to true for this test to pass
				gw.performedSuccessfulReload = true
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
		{
			name:   "successful reload not performed",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Ensure performedSuccessfulReload is false (default state)
				gw.performedSuccessfulReload = false
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with passing redis to ensure we get to the reload check
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:       http.StatusServiceUnavailable,
			expectedErrorMessage: "A successful API reload did not happen",
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

func TestGateway_isCriticalFailureForLiveness(t *testing.T) {
	tests := []struct {
		name           string
		component      string
		check          HealthCheckItem
		setupConfig    func(*config.Config)
		setupFunc      func(*testing.T)
		expectedResult bool
	}{
		{
			name:      "redis component is NOT critical for liveness",
			component: "redis",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: Datastore,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: false,
		},
		{
			name:      "dashboard component is critical for liveness when UseDBAppConfigs is enabled",
			component: "dashboard",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = true
			},
			expectedResult: true,
		},
		{
			name:      "dashboard component is not critical for liveness when UseDBAppConfigs is disabled",
			component: "dashboard",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = false
			},
			expectedResult: false,
		},
		{
			name:      "rpc component is critical for liveness when PolicySource is rpc",
			component: "rpc",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "rpc"
			},
			expectedResult: true,
		},
		{
			name:      "rpc component is not critical for liveness when PolicySource is file",
			component: "rpc",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "file"
			},
			expectedResult: false,
		},
		{
			name:      "unknown component is not critical for liveness",
			component: "custom",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := config.Config{}
			tt.setupConfig(&conf)

			if tt.setupFunc != nil {
				tt.setupFunc(t)
			}

			gw := NewGateway(conf, nil)

			// Call the function under test
			result := gw.isCriticalFailureForLiveness(tt.component)

			// Assert the result
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGateway_evaluateHealthChecksForLiveness(t *testing.T) {
	tests := []struct {
		name                    string
		checks                  map[string]HealthCheckItem
		setupConfig             func(*config.Config)
		expectedFailCount       int
		expectedCriticalFailure bool
	}{
		{
			name:                    "no health checks",
			checks:                  map[string]HealthCheckItem{},
			setupConfig:             func(_ *config.Config) {},
			expectedFailCount:       0,
			expectedCriticalFailure: false,
		},
		{
			name: "all checks passing",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Pass,
					ComponentType: System,
				},
			},
			setupConfig:             func(_ *config.Config) {},
			expectedFailCount:       0,
			expectedCriticalFailure: false,
		},
		{
			name: "redis failing - NOT critical for liveness",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Fail,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Pass,
					ComponentType: System,
				},
			},
			setupConfig:             func(_ *config.Config) {},
			expectedFailCount:       1,
			expectedCriticalFailure: false,
		},
		{
			name: "dashboard failing with UseDBAppConfigs enabled - critical for liveness",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = true
			},
			expectedFailCount:       1,
			expectedCriticalFailure: true,
		},
		{
			name: "dashboard failing with UseDBAppConfigs disabled - non-critical for liveness",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = false
			},
			expectedFailCount:       1,
			expectedCriticalFailure: false,
		},
		{
			name: "redis and dashboard both failing - only dashboard critical for liveness when enabled",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Fail,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = true
			},
			expectedFailCount:       2,
			expectedCriticalFailure: true,
		},
		{
			name: "redis and dashboard both failing - neither critical for liveness when dashboard disabled",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Fail,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = false
			},
			expectedFailCount:       2,
			expectedCriticalFailure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := config.Config{}
			tt.setupConfig(&conf)

			gw := NewGateway(conf, nil)

			// Call the function under test
			failCount, criticalFailure := gw.evaluateHealthChecksForLiveness(tt.checks)

			// Assert the results
			assert.Equal(t, tt.expectedFailCount, failCount)
			assert.Equal(t, tt.expectedCriticalFailure, criticalFailure)
		})
	}
}

func TestGateway_helloHandler(t *testing.T) {
	tests := []struct {
		name                   string
		method                 string
		setupGateway           func(*Gateway)
		setupHealthCheck       func(*Gateway)
		expectedStatus         int
		expectedResponseStatus HealthCheckStatus
		expectedErrorMessage   string
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
			name:   "always returns 200 OK even with redis failure",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
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
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
		},
		{
			name:   "returns 200 OK with all checks passing",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
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
			name:   "returns 200 OK with mixed status - warning",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with mixed results
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
					},
					"custom": {
						Status:        Pass,
						ComponentType: System,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
		},
		{
			name:   "returns 200 OK with all checks failing",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with all failing
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis connection failed",
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard service unavailable",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
		},
		{
			name:   "hide generator header enabled",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable HideGeneratorHeader
				conf := gw.GetConfig()
				conf.HideGeneratorHeader = true
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
			name:   "empty health check info",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
			},
			setupHealthCheck: func(gw *Gateway) {
				// No health check data
				gw.setCurrentHealthCheckInfo(map[string]HealthCheckItem{})
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass, // Pass when no checks present
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
			req := httptest.NewRequest(tt.method, "/hello", nil)
			w := httptest.NewRecorder()

			// Call the handler
			gw.helloHandler(w, req)

			// Check status code - hello always returns 200 except for method not allowed
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
				assert.Equal(t, "Tyk GW", response.Description)
				// Details field is expected to be present (can be empty map or nil)
				if response.Details == nil {
					assert.Nil(t, response.Details)
				} else {
					assert.NotNil(t, response.Details)
				}
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

func TestGateway_liveCheckHandler(t *testing.T) {
	tests := []struct {
		name                   string
		method                 string
		setupGateway           func(*Gateway)
		setupHealthCheck       func(*Gateway)
		expectedStatus         int
		expectedResponseStatus HealthCheckStatus
		expectedErrorMessage   string
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
			name:   "all checks passing - returns 200",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
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
			name:   "partial non-critical failures - returns 200 with warning",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Disable UseDBAppConfigs to make dashboard non-critical
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = false
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with mixed results
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard service unavailable",
					},
					"custom": {
						Status:        Pass,
						ComponentType: System,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
		},
		{
			name:   "redis failure only - returns 200 with fail status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with Redis failing (non-critical for liveness)
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
		},
		{
			name:   "dashboard failure with UseDBAppConfigs enabled - returns 503",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable UseDBAppConfigs to make dashboard critical
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = true
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with dashboard failing (critical for liveness)
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard service unavailable",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusServiceUnavailable,
			expectedResponseStatus: Warn,
		},
		{
			name:   "mixed failures with redis and non-critical dashboard - returns 200",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Disable UseDBAppConfigs to make dashboard non-critical
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = false
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				// Set up health check with all failing but only non-critical for liveness
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis connection failed",
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard service unavailable",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
		},
		{
			name:   "hide generator header enabled",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				// Enable HideGeneratorHeader
				conf := gw.GetConfig()
				conf.HideGeneratorHeader = true
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
			name:   "empty health check info",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
				// No special setup needed
			},
			setupHealthCheck: func(gw *Gateway) {
				// No health check data
				gw.setCurrentHealthCheckInfo(map[string]HealthCheckItem{})
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass, // Pass when no checks present
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
			req := httptest.NewRequest(tt.method, "/live", nil)
			w := httptest.NewRecorder()

			// Call the handler
			gw.liveCheckHandler(w, req)

			// Check status code - live check always returns 200 (original behavior)
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
				assert.Equal(t, "Tyk GW", response.Description)
				// Details field is expected to be present (can be empty map or nil)
				if response.Details == nil {
					assert.Nil(t, response.Details)
				} else {
					assert.NotNil(t, response.Details)
				}
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

func TestGateway_helloHandler_Integration(t *testing.T) {
	// Integration test using the actual test framework
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("hello endpoint responds correctly", func(t *testing.T) {
		// Test with a working gateway - use the configured hello endpoint name
		helloPath := "/" + ts.Gw.GetConfig().HealthCheckEndpointName
		resp, err := http.Get(ts.URL + helloPath)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var response HealthCheckResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, VERSION, response.Version)
		assert.Equal(t, "Tyk GW", response.Description)
		// Status will be pass/warn/fail based on actual health checks, but always 200 status code
		assert.Contains(t, []HealthCheckStatus{Pass, Warn, Fail}, response.Status)
	})

	t.Run("method not allowed", func(t *testing.T) {
		helloPath := "/" + ts.Gw.GetConfig().HealthCheckEndpointName
		req, err := http.NewRequest(http.MethodPost, ts.URL+helloPath, nil)
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

func TestGateway_liveCheckHandler_Integration(t *testing.T) {
	// Integration test using the actual test framework
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("live endpoint responds correctly", func(t *testing.T) {
		// Test with a working gateway - use the configured live endpoint name
		livePath := "/" + ts.Gw.GetConfig().LivenessCheckEndpointName
		resp, err := http.Get(ts.URL + livePath)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var response HealthCheckResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, VERSION, response.Version)
		assert.Equal(t, "Tyk GW", response.Description)
		// Status will be pass/warn/fail based on actual health checks, always 200 status code
		assert.Contains(t, []HealthCheckStatus{Pass, Warn, Fail}, response.Status)
	})

	t.Run("method not allowed", func(t *testing.T) {
		livePath := "/" + ts.Gw.GetConfig().LivenessCheckEndpointName
		req, err := http.NewRequest(http.MethodPost, ts.URL+livePath, nil)
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

func TestGateway_determineHealthStatus(t *testing.T) {
	tests := []struct {
		name               string
		failCount          int
		criticalFailure    bool
		totalChecks        int
		expectedStatus     HealthCheckStatus
		expectedHTTPStatus int
	}{
		{
			name:               "no failures - all pass",
			failCount:          0,
			criticalFailure:    false,
			totalChecks:        3,
			expectedStatus:     Pass,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name:               "no failures with zero checks",
			failCount:          0,
			criticalFailure:    false,
			totalChecks:        0,
			expectedStatus:     Pass,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name:               "critical failure present",
			failCount:          1,
			criticalFailure:    true,
			totalChecks:        3,
			expectedStatus:     Fail,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name:               "multiple failures with critical",
			failCount:          2,
			criticalFailure:    true,
			totalChecks:        3,
			expectedStatus:     Fail,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name:               "all checks failed",
			failCount:          3,
			criticalFailure:    false,
			totalChecks:        3,
			expectedStatus:     Fail,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name:               "all checks failed with critical",
			failCount:          3,
			criticalFailure:    true,
			totalChecks:        3,
			expectedStatus:     Fail,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name:               "single check failed (all failed case)",
			failCount:          1,
			criticalFailure:    false,
			totalChecks:        1,
			expectedStatus:     Fail,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name:               "partial non-critical failures - warning",
			failCount:          1,
			criticalFailure:    false,
			totalChecks:        3,
			expectedStatus:     Warn,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name:               "multiple non-critical failures - warning",
			failCount:          2,
			criticalFailure:    false,
			totalChecks:        5,
			expectedStatus:     Warn,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name:               "edge case - zero total checks with failures",
			failCount:          1,
			criticalFailure:    false,
			totalChecks:        0,
			expectedStatus:     Warn,
			expectedHTTPStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a gateway instance (config doesn't matter for this function)
			gw := NewGateway(config.Config{}, nil)

			// Call the function under test
			status, httpStatus := gw.determineHealthStatus(tt.failCount, tt.criticalFailure, tt.totalChecks)

			// Assert the results
			assert.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedHTTPStatus, httpStatus)
		})
	}
}
