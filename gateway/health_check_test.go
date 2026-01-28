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
	"github.com/TykTechnologies/tyk/rpc"
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
		tt := tt
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

func TestGateway_isCriticalFailure(t *testing.T) {
	tests := []struct {
		name           string
		component      string
		check          HealthCheckItem
		setupConfig    func(*config.Config)
		setupFunc      func(*testing.T)
		expectedResult bool
	}{
		{
			name:      "redis component is always critical",
			component: "redis",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: Datastore,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: true,
		},
		{
			name:      "dashboard component is critical when UseDBAppConfigs is enabled",
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
			name:      "dashboard component is not critical when UseDBAppConfigs is disabled",
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
			name:      "rpc component is critical when PolicySource is rpc",
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
			name:      "rpc component is not critical when PolicySource is not rpc",
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
			name:      "unknown component is not critical",
			component: "unknown",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: false,
		},
		{
			name:      "custom component is not critical",
			component: "custom-service",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: false,
		},
		{
			name:      "redis component with pass status (edge case)",
			component: "redis",
			check: HealthCheckItem{
				Status:        Pass,
				ComponentType: Datastore,
			},
			setupConfig:    func(_ *config.Config) {},
			expectedResult: true, // Redis is always critical regardless of status
		},
		{
			name:      "dashboard with UseDBAppConfigs enabled and warn status",
			component: "dashboard",
			check: HealthCheckItem{
				Status:        Warn,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = true
			},
			expectedResult: true, // Critical based on component and config, not status
		},
		{
			name:      "rpc component is NOT critical when PolicySource is rpc but in emergency mode",
			component: "rpc",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "rpc"
			},
			setupFunc: func(t *testing.T) {
				rpc.SetEmergencyMode(t, true)
			},
			expectedResult: false,
		},
		{
			name:      "rpc component is critical when PolicySource is rpc and NOT in emergency mode",
			component: "rpc",
			check: HealthCheckItem{
				Status:        Fail,
				ComponentType: System,
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "rpc"
			},
			setupFunc: func(t *testing.T) {
				rpc.SetEmergencyMode(t, false)
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a new gateway instance for each test
			conf := config.Config{}
			tt.setupConfig(&conf)

			// Setup emergency mode if needed
			if tt.setupFunc != nil {
				tt.setupFunc(t)
			}

			gw := NewGateway(conf, nil)

			// Call the function under test
			result := gw.isCriticalFailure(tt.component)

			// Assert the result
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestGateway_evaluateHealthChecks(t *testing.T) {
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
			name: "redis failing - critical failure",
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
			expectedCriticalFailure: true,
		},
		{
			name: "dashboard failing with UseDBAppConfigs enabled - critical failure",
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
			name: "dashboard failing with UseDBAppConfigs disabled - non-critical failure",
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
			name: "rpc failing with PolicySource rpc - critical failure",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"rpc": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "rpc"
			},
			expectedFailCount:       1,
			expectedCriticalFailure: true,
		},
		{
			name: "rpc failing with PolicySource file - non-critical failure",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"rpc": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.Policies.PolicySource = "file"
			},
			expectedFailCount:       1,
			expectedCriticalFailure: false,
		},
		{
			name: "multiple failures with one critical",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Fail,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
				"custom": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = false // dashboard not critical
			},
			expectedFailCount:       3,
			expectedCriticalFailure: true, // redis is critical
		},
		{
			name: "multiple non-critical failures",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Pass,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Fail,
					ComponentType: System,
				},
				"custom": {
					Status:        Fail,
					ComponentType: System,
				},
			},
			setupConfig: func(conf *config.Config) {
				conf.UseDBAppConfigs = false // dashboard not critical
			},
			expectedFailCount:       2,
			expectedCriticalFailure: false,
		},
		{
			name: "warning status not counted as failure",
			checks: map[string]HealthCheckItem{
				"redis": {
					Status:        Warn,
					ComponentType: Datastore,
				},
				"dashboard": {
					Status:        Warn,
					ComponentType: System,
				},
			},
			setupConfig:             func(_ *config.Config) {},
			expectedFailCount:       0,
			expectedCriticalFailure: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a new gateway instance for each test
			conf := config.Config{}
			tt.setupConfig(&conf)
			gw := NewGateway(conf, nil)

			// Call the function under test
			failCount, criticalFailure := gw.evaluateHealthChecks(tt.checks)

			// Assert the results
			assert.Equal(t, tt.expectedFailCount, failCount)
			assert.Equal(t, tt.expectedCriticalFailure, criticalFailure)
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
	}{
		{
			name:             "method not allowed - POST",
			method:           http.MethodPost,
			setupGateway:     func(_ *Gateway) {},
			setupHealthCheck: func(_ *Gateway) {},
			expectedStatus:   http.StatusMethodNotAllowed,
		},
		{
			name:             "method not allowed - PUT",
			method:           http.MethodPut,
			setupGateway:     func(_ *Gateway) {},
			setupHealthCheck: func(_ *Gateway) {},
			expectedStatus:   http.StatusMethodNotAllowed,
		},
		{
			name:   "all health checks pass - returns 200 OK with Pass status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
			},
			setupHealthCheck: func(gw *Gateway) {
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
			name:   "redis health check failed - still returns 200 OK with Fail status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Connection failed",
					},
					"dashboard": {
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
			name:   "all health checks failed - returns 200 OK with Fail status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis connection failed",
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
		},
		{
			name:   "partial health check failures - returns 200 OK with Warn status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard connection failed",
					},
					"rpc": {
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
			name:   "empty health check data - returns 200 OK with Pass status",
			method: http.MethodGet,
			setupGateway: func(_ *Gateway) {
			},
			setupHealthCheck: func(gw *Gateway) {
				gw.setCurrentHealthCheckInfo(map[string]HealthCheckItem{})
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
		},
		{
			name:   "hide generator header enabled - returns 200 OK",
			method: http.MethodGet,
			setupGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.HideGeneratorHeader = true
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, nil)

			tt.setupGateway(gw)
			tt.setupHealthCheck(gw)

			req := httptest.NewRequest(tt.method, "/hello", nil)
			w := httptest.NewRecorder()

			gw.liveCheckHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code != http.StatusMethodNotAllowed {
				assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			}

			switch tt.expectedStatus {
			case http.StatusOK:
				var response HealthCheckResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				assert.Equal(t, tt.expectedResponseStatus, response.Status)
				assert.Equal(t, VERSION, response.Version)
				assert.Equal(t, "Tyk GW", response.Description)
			case http.StatusMethodNotAllowed:
				var errorResponse apiStatusMessage
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(t, err)

				assert.Equal(t, "error", errorResponse.Status)
				assert.Equal(t, "Method Not Allowed", errorResponse.Message)
			}
		})
	}
}

func TestGateway_liveCheckHandler_vs_readinessHandler(t *testing.T) {
	tests := []struct {
		name                    string
		setupHealthCheck        func(*Gateway)
		expectedLiveStatus      int
		expectedLiveResponse    HealthCheckStatus
		expectedReadinessStatus int
		expectedReadinessError  string
	}{
		{
			name: "redis failed - /hello returns 200 OK, /ready returns 503",
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
				gw.performedSuccessfulReload = true
			},
			expectedLiveStatus:      http.StatusOK,
			expectedLiveResponse:    Fail,
			expectedReadinessStatus: http.StatusServiceUnavailable,
			expectedReadinessError:  "Redis connection not available",
		},
		{
			name: "dashboard failed (UseDBAppConfigs disabled) - both return 200 OK",
			setupHealthCheck: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = false
				gw.SetConfig(conf)

				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
				gw.performedSuccessfulReload = true
			},
			expectedLiveStatus:      http.StatusOK,
			expectedLiveResponse:    Warn,
			expectedReadinessStatus: http.StatusOK,
		},
		{
			name: "all checks pass - both return 200 OK",
			setupHealthCheck: func(gw *Gateway) {
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
				gw.performedSuccessfulReload = true
			},
			expectedLiveStatus:      http.StatusOK,
			expectedLiveResponse:    Pass,
			expectedReadinessStatus: http.StatusOK,
		},
		{
			name: "no successful reload - /hello returns 200 OK, /ready returns 503",
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
				gw.performedSuccessfulReload = false
			},
			expectedLiveStatus:      http.StatusOK,
			expectedLiveResponse:    Pass,
			expectedReadinessStatus: http.StatusServiceUnavailable,
			expectedReadinessError:  "A successful API reload did not happen",
		},
		{
			name: "multiple failures - /hello returns 200 OK with Warn, /ready checks Redis first",
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard failed",
					},
					"rpc": {
						Status:        Fail,
						ComponentType: System,
						Output:        "RPC failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
				gw.performedSuccessfulReload = true
			},
			expectedLiveStatus:      http.StatusOK,
			expectedLiveResponse:    Warn,
			expectedReadinessStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, nil)
			tt.setupHealthCheck(gw)

			liveReq := httptest.NewRequest(http.MethodGet, "/hello", nil)
			liveW := httptest.NewRecorder()
			gw.liveCheckHandler(liveW, liveReq)

			assert.Equal(t, tt.expectedLiveStatus, liveW.Code)
			assert.Equal(t, "application/json", liveW.Header().Get("Content-Type"))

			var liveResponse HealthCheckResponse
			err := json.Unmarshal(liveW.Body.Bytes(), &liveResponse)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLiveResponse, liveResponse.Status)

			readyReq := httptest.NewRequest(http.MethodGet, "/ready", nil)
			readyW := httptest.NewRecorder()
			gw.readinessHandler(readyW, readyReq)

			assert.Equal(t, tt.expectedReadinessStatus, readyW.Code)
			assert.Equal(t, "application/json", readyW.Header().Get("Content-Type"))

			if tt.expectedReadinessStatus == http.StatusOK {
				var readyResponse HealthCheckResponse
				err := json.Unmarshal(readyW.Body.Bytes(), &readyResponse)
				require.NoError(t, err)
				assert.Equal(t, Pass, readyResponse.Status)
			} else if tt.expectedReadinessError != "" {
				var errorResponse apiStatusMessage
				err := json.Unmarshal(readyW.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Equal(t, "error", errorResponse.Status)
				assert.Equal(t, tt.expectedReadinessError, errorResponse.Message)
			}
		})
	}
}

func TestGateway_liveCheckHandler_EdgeCases(t *testing.T) {
	tests := []struct {
		name                   string
		setupGateway           func(*Gateway)
		setupHealthCheck       func(*Gateway)
		expectedStatus         int
		expectedResponseStatus HealthCheckStatus
		testDescription        string
	}{
		{
			name: "custom health check endpoint name configuration",
			setupGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.HealthCheckEndpointName = "custom-health"
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
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
			testDescription:        "Custom endpoint name should not affect handler behavior",
		},
		{
			name: "UseDBAppConfigs enabled with dashboard failure",
			setupGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.UseDBAppConfigs = true
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Dashboard connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
			testDescription:        "Dashboard failure with UseDBAppConfigs should return 200 OK with Warn",
		},
		{
			name: "RPC policy source with RPC failure",
			setupGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.Policies.PolicySource = "rpc"
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"rpc": {
						Status:        Fail,
						ComponentType: System,
						Output:        "RPC connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
			testDescription:        "RPC failure should return 200 OK with Warn status",
		},
		{
			name: "file policy source with RPC failure",
			setupGateway: func(gw *Gateway) {
				conf := gw.GetConfig()
				conf.Policies.PolicySource = "file"
				gw.SetConfig(conf)
			},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"rpc": {
						Status:        Fail,
						ComponentType: System,
						Output:        "RPC connection failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
			testDescription:        "RPC failure with file policy source should return 200 OK with Warn",
		},
		{
			name:         "warning status in health checks",
			setupGateway: func(_ *Gateway) {},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Warn,
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
			testDescription:        "Warning status should not count as failure",
		},
		{
			name:         "single component with different status values",
			setupGateway: func(_ *Gateway) {},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Fail,
						ComponentType: Datastore,
						Output:        "Redis completely down",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Fail,
			testDescription:        "Single failing component should result in Fail status",
		},
		{
			name:         "multiple mixed component types",
			setupGateway: func(_ *Gateway) {},
			setupHealthCheck: func(gw *Gateway) {
				healthInfo := map[string]HealthCheckItem{
					"redis": {
						Status:        Pass,
						ComponentType: Datastore,
					},
					"dashboard": {
						Status:        Pass,
						ComponentType: System,
					},
					"custom-service": {
						Status:        Warn,
						ComponentType: System,
					},
					"another-service": {
						Status:        Fail,
						ComponentType: System,
						Output:        "Custom service failed",
					},
				}
				gw.setCurrentHealthCheckInfo(healthInfo)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Warn,
			testDescription:        "Mixed component results should return Warn when some fail",
		},
		{
			name:         "nil health check data handling",
			setupGateway: func(_ *Gateway) {},
			setupHealthCheck: func(gw *Gateway) {
				gw.setCurrentHealthCheckInfo(nil)
			},
			expectedStatus:         http.StatusOK,
			expectedResponseStatus: Pass,
			testDescription:        "Nil health check data should be handled gracefully",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(config.Config{}, nil)

			tt.setupGateway(gw)
			tt.setupHealthCheck(gw)

			req := httptest.NewRequest(http.MethodGet, "/hello", nil)
			w := httptest.NewRecorder()

			gw.liveCheckHandler(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, tt.testDescription)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response HealthCheckResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedResponseStatus, response.Status, tt.testDescription)
			assert.Equal(t, VERSION, response.Version)
			assert.Equal(t, "Tyk GW", response.Description)
		})
	}
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
		tt := tt
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
