package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/netutil"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGateway_afterConfSetup(t *testing.T) {

	tests := []struct {
		name           string
		initialConfig  config.Config
		expectedConfig config.Config
	}{
		{
			name: "slave options test",
			initialConfig: config.Config{
				SlaveOptions: config.SlaveOptionsConfig{
					UseRPC: true,
				},
			},
			expectedConfig: config.Config{
				SlaveOptions: config.SlaveOptionsConfig{
					UseRPC:                   true,
					GroupID:                  "ungrouped",
					CallTimeout:              30,
					PingTimeout:              60,
					KeySpaceSyncInterval:     10,
					RPCCertCacheExpiration:   3600,
					RPCGlobalCacheExpiration: 30,
				},
				AnalyticsConfig: config.AnalyticsConfigConfig{
					PurgeInterval: 10,
				},
				HealthCheckEndpointName:    "hello",
				ReadinessCheckEndpointName: "ready",
			},
		},
		{
			name: "opentelemetry options test",
			initialConfig: config.Config{
				OpenTelemetry: otel.OpenTelemetry{
					Enabled: true,
				},
			},
			expectedConfig: config.Config{
				OpenTelemetry: otel.OpenTelemetry{
					Enabled:            true,
					Exporter:           "grpc",
					Endpoint:           "localhost:4317",
					ResourceName:       "tyk-gateway",
					SpanProcessorType:  "batch",
					ConnectionTimeout:  1,
					ContextPropagation: "tracecontext",
					Sampling: otel.Sampling{
						Type: "AlwaysOn",
					},
				},
				AnalyticsConfig: config.AnalyticsConfigConfig{
					PurgeInterval: 10,
				},
				HealthCheckEndpointName:    "hello",
				ReadinessCheckEndpointName: "ready",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(tt.initialConfig, context.Background())
			gw.afterConfSetup()

			assert.Equal(t, tt.expectedConfig, gw.GetConfig())

		})
	}
}

func TestGateway_apisByIDLen(t *testing.T) {
	tcs := []struct {
		name     string
		APIs     []string
		expected int
	}{
		{
			name:     "empty apis",
			APIs:     []string{},
			expected: 0,
		},
		{
			name:     "one api",
			APIs:     []string{"api1"},
			expected: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			for i := range tc.APIs {
				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.APIID = tc.APIs[i]
					spec.UseKeylessAccess = false
					spec.OrgID = "default"
				})
			}

			actual := ts.Gw.apisByIDLen()

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGateway_policiesByIDLen(t *testing.T) {
	tcs := []struct {
		name     string
		policies []string
		expected int
	}{
		{
			name:     "empty policies",
			policies: []string{},
			expected: 0,
		},
		{
			name:     "one policy",
			policies: []string{"policy1"},
			expected: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			for _, pol := range tc.policies {
				ts.CreatePolicy(func(p *user.Policy) {
					p.Name = pol
				})
			}

			actual := ts.Gw.PolicyCount()

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGateway_SyncResourcesWithReload(t *testing.T) {
	retryAttempts := 2
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.ResourceSync.RetryAttempts = retryAttempts
		globalConf.ResourceSync.Interval = 1
	})
	defer ts.Close()

	var syncErr = errors.New("sync error")
	syncFuncSuccessAt := func(t *testing.T, successAt int) (func() (int, error), *int) {
		t.Helper()
		var hitCount int
		return func() (int, error) {
			hitCount++
			if hitCount == successAt {
				return 10, nil
			}
			return 0, syncErr
		}, &hitCount
	}

	t.Run("invalid resource", func(t *testing.T) {
		t.Parallel()
		syncFunc, hitCounter := syncFuncSuccessAt(t, 0)
		resourceCount, err := syncResourcesWithReload("unknown-resource", ts.Gw.GetConfig(), syncFunc)
		assert.Error(t, ErrSyncResourceNotKnown, err)
		assert.Zero(t, resourceCount)
		assert.Zero(t, *hitCounter)
	})

	t.Run("sync success at first try", func(t *testing.T) {
		t.Parallel()
		syncFunc, hitCounter := syncFuncSuccessAt(t, 1)
		resourceCount, err := syncResourcesWithReload("apis", ts.Gw.GetConfig(), syncFunc)
		assert.NoError(t, err)
		assert.Equal(t, 10, resourceCount)
		assert.Equal(t, 1, *hitCounter)
	})

	t.Run("sync failed after retries", func(t *testing.T) {
		t.Parallel()
		syncFunc, hitCounter := syncFuncSuccessAt(t, 5)
		startTime := time.Now()
		resourceCount, err := syncResourcesWithReload("apis", ts.Gw.GetConfig(), syncFunc)
		assert.Greater(t, time.Since(startTime), time.Second*3)
		assert.ErrorIs(t, err, syncErr)
		assert.Zero(t, resourceCount)
		assert.Equal(t, 3, *hitCounter)
	})

	t.Run("sync success after first retry", func(t *testing.T) {
		t.Parallel()
		syncFunc, hitCounter := syncFuncSuccessAt(t, 2)
		startTime := time.Now()
		resourceCount, err := syncResourcesWithReload("apis", ts.Gw.GetConfig(), syncFunc)
		assert.Greater(t, time.Since(startTime), time.Second*1)
		assert.NoError(t, err)
		assert.Equal(t, 10, resourceCount)
		assert.Equal(t, 2, *hitCounter)
	})

}

type gatewayGetHostDetailsTestCheckFn func(*testing.T, *test.BufferedLogger, *Gateway)

func gatewayGetHostDetailsTestHasErr(wantErr bool, errorText string) gatewayGetHostDetailsTestCheckFn {
	return func(t *testing.T, bl *test.BufferedLogger, _ *Gateway) {
		t.Helper()
		logs := bl.GetLogs(logrus.ErrorLevel)
		if wantErr {
			assert.NotEmpty(t, logs, "Expected error logs but got none")
			if errorText != "" {
				for _, log := range logs {
					assert.Contains(t, log.Message, errorText, "Expected log message to contain %q", errorText)
				}
			}
		} else {
			assert.Empty(t, logs, "Expected no error logs but got some")
		}
	}
}

func gatewayGetHostDetailsTestAddress() gatewayGetHostDetailsTestCheckFn {
	return func(t *testing.T, _ *test.BufferedLogger, gw *Gateway) {
		t.Helper()
		assert.NotNil(t, net.ParseIP(gw.hostDetails.Address))
	}
}

func defineGatewayGetHostDetailsTests() []struct {
	name                string
	before              func(*Gateway)
	netutilGetIpAddress func() ([]string, error)
	checks              []gatewayGetHostDetailsTestCheckFn
} {
	var check = func(fns ...gatewayGetHostDetailsTestCheckFn) []gatewayGetHostDetailsTestCheckFn { return fns }

	return []struct {
		name                string
		before              func(*Gateway)
		netutilGetIpAddress func() ([]string, error)
		checks              []gatewayGetHostDetailsTestCheckFn
	}{
		{
			name: "fail-read-pid",
			before: func(gw *Gateway) {
				gw.SetConfig(config.Config{
					ListenAddress: "127.0.0.1",
				})
			},
			checks: check(
				gatewayGetHostDetailsTestHasErr(true, "Error opening file"),
			),
		},
		{
			name: "success-listen-address-set",
			before: func(gw *Gateway) {
				gw.SetConfig(config.Config{
					ListenAddress: "127.0.0.1",
				})
			},
			checks: check(
				gatewayGetHostDetailsTestHasErr(false, ""),
				gatewayGetHostDetailsTestAddress(),
			),
		},
		{
			name: "success-listen-address-not-set",
			before: func(gw *Gateway) {
				gw.SetConfig(config.Config{
					ListenAddress: "",
				})
			},
			checks: check(
				gatewayGetHostDetailsTestHasErr(false, ""),
				gatewayGetHostDetailsTestAddress(),
			),
		},
		{
			name: "fail-getting-network-address",
			before: func(gw *Gateway) {
				gw.SetConfig(config.Config{
					ListenAddress: "",
				})
			},
			netutilGetIpAddress: func() ([]string, error) { return nil, fmt.Errorf("Error getting network addresses") },
			checks: check(
				gatewayGetHostDetailsTestHasErr(true, "Error getting network addresses"),
			),
		},
	}
}

func TestGatewayGetHostDetails(t *testing.T) {
	// This test has several issue over globals, `mainLog`, etc.
	// There's only rewriting it.
	t.Skip()

	var (
		orig_mainLog      = mainLog
		orig_getIpAddress = netutil.GetIpAddress
		bl                = test.NewBufferingLogger()
	)

	tests := defineGatewayGetHostDetailsTests()

	// restore the original functions
	defer func() {
		mainLog = orig_mainLog
		getIpAddress = orig_getIpAddress
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// clear logger mock buffer
			bl.ClearLogs()
			// replace functions with mocks
			mainLog = bl.Logger.WithField("prefix", "test")

			if tt.netutilGetIpAddress != nil {
				getIpAddress = tt.netutilGetIpAddress
			}

			gw := &Gateway{}

			if tt.before != nil {
				tt.before(gw)
			}

			gw.getHostDetails()
			for _, c := range tt.checks {
				c(t, bl, gw)
			}
		})
	}
}

func TestGateway_gracefulShutdown(t *testing.T) {
	tests := []struct {
		name           string
		setupGateway   func() *Gateway
		setupContext   func() (context.Context, context.CancelFunc)
		expectError    bool
		errorContains  string
		validateResult func(*testing.T, *Gateway)
	}{
		{
			name: "successful shutdown with no servers",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{},
					},
				}
				gw.SetConfig(config.Config{})
				gw.cacheCreate()
				return gw
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
		},
		{
			name: "successful shutdown with HTTP servers",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port: 8080,
								httpServer: &http.Server{
									Addr: ":8080",
								},
							},
							{
								port: 8081,
								httpServer: &http.Server{
									Addr: ":8081",
								},
							},
						},
					},
				}
				gw.SetConfig(config.Config{})
				gw.cacheCreate()
				return gw
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
		},
		{
			name: "shutdown with timeout context",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port: 8080,
								httpServer: &http.Server{
									Addr: ":8080",
								},
							},
						},
					},
				}
				gw.SetConfig(config.Config{})
				gw.cacheCreate()
				return gw
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				// Very short timeout to test timeout handling
				return context.WithTimeout(context.Background(), 1*time.Nanosecond)
			},
			expectError: false, // Timeout is handled gracefully, not an error
		},
		{
			name: "shutdown with nil httpServer (should skip)",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:       8080,
								httpServer: nil, // nil server should be skipped
							},
							{
								port: 8081,
								httpServer: &http.Server{
									Addr: ":8081",
								},
							},
						},
					},
				}
				gw.SetConfig(config.Config{})
				gw.cacheCreate()
				return gw
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
		},
		{
			name: "shutdown with empty proxy list",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{},
					},
				}
				gw.SetConfig(config.Config{})
				gw.cacheCreate()
				return gw
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := tt.setupGateway()
			ctx, cancel := tt.setupContext()
			defer cancel()

			err := gw.gracefulShutdown(ctx)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}

			if tt.validateResult != nil {
				tt.validateResult(t, gw)
			}
		})
	}
}

func TestGateway_gracefulShutdown_ConcurrentSafety(t *testing.T) {
	// Test that gracefulShutdown is safe to call concurrently
	gw := &Gateway{
		DefaultProxyMux: &proxyMux{
			proxies: []*proxy{
				{
					port: 8080,
					httpServer: &http.Server{
						Addr: ":8080",
					},
				},
			},
		},
	}
	gw.SetConfig(config.Config{})
	gw.cacheCreate()

	var wg sync.WaitGroup
	errors := make(chan error, 3)

	// Start multiple graceful shutdowns concurrently
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := gw.gracefulShutdown(ctx)
			errors <- err
		}()
	}

	wg.Wait()
	close(errors)

	// At least one should succeed, others might fail due to already closed servers
	var successCount int
	for err := range errors {
		if err == nil {
			successCount++
		}
	}

	if successCount == 0 {
		t.Error("expected at least one graceful shutdown to succeed")
	}
}

// Test helper to create a Gateway with proper cache initialization
func createTestGateway() *Gateway {
	gw := &Gateway{
		DefaultProxyMux: &proxyMux{
			proxies: []*proxy{},
		},
	}

	// Initialize config
	conf := config.Config{}
	gw.SetConfig(conf)
	gw.cacheCreate()

	return gw
}

func TestGateway_cacheClose(t *testing.T) {
	// Test that cacheClose properly closes all caches
	gw := createTestGateway()

	// Verify caches are created and working
	if gw.SessionCache == nil {
		t.Error("SessionCache should be initialized")
	}

	// Call cacheClose
	gw.cacheClose()

	// Note: We can't easily test that caches are actually closed
	// since the cache.Close() method doesn't expose internal state
	// This test mainly ensures cacheClose doesn't panic
}
