package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/again"
	"github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/netutil"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/tcp"
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
					UseRPC:                      true,
					GroupID:                     "ungrouped",
					CallTimeout:                 30,
					PingTimeout:                 60,
					KeySpaceSyncInterval:        10,
					RPCCertCacheExpiration:      3600,
					RPCGlobalCacheExpiration:    30,
					RPCCertFetchMaxElapsedTime:  30,
					RPCCertFetchInitialInterval: 0.1,
					RPCCertFetchMaxInterval:     2,
					RPCCertFetchRetryEnabled:    func() *bool { b := true; return &b }(),
					RPCCertFetchMaxRetries:      func() *int { i := 5; return &i }(),
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
		assert.Greater(t, time.Since(startTime), time.Second*2)
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

	t.Run("RPC timeout triggers emergency mode and loads from backup", func(t *testing.T) {
		t.Parallel()

		// Configure gateway for RPC mode
		conf := ts.Gw.GetConfig()
		conf.SlaveOptions.UseRPC = true

		// Create a sync function that simulates timeout errors initially, then succeeds when emergency mode is enabled
		var hitCount int
		timeoutError := errors.New("Cannot obtain response during timeout=30s")

		syncFunc := func() (int, error) {
			hitCount++

			// Always fail with timeout for the first retryAttempts+1 attempts (normal + last attempt)
			// This ensures emergency mode gets triggered properly
			if hitCount <= retryAttempts+1 {
				return 0, timeoutError
			}

			// Succeed when emergency mode is enabled (backup loading)
			// This will be called after emergency mode is enabled
			return 5, nil // Simulate loading 5 items from backup
		}

		// Ensure we start without emergency mode
		rpc.ResetEmergencyMode()
		defer rpc.ResetEmergencyMode()

		// Test the sync with timeout -> emergency mode -> success flow
		resourceCount, err := syncResourcesWithReload("policies", conf, syncFunc)

		// Should succeed after triggering emergency mode
		assert.NoError(t, err)
		assert.Equal(t, 5, resourceCount)

		// Should have attempted retries + 1 emergency mode attempt
		assert.Equal(t, retryAttempts+2, hitCount)

		// Emergency mode should be enabled
		assert.True(t, rpc.IsEmergencyMode())
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
						again:   again.New(),
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
						again: again.New(),
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
						again: again.New(),
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
						again: again.New(),
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
						again:   again.New(),
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
			again: again.New(),
		},
	}
	gw.SetConfig(config.Config{})
	gw.cacheCreate()

	var wg sync.WaitGroup
	errorChan := make(chan error, 3)

	// Start multiple graceful shutdowns concurrently
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := gw.gracefulShutdown(ctx)
			errorChan <- err
		}()
	}

	wg.Wait()
	close(errorChan)

	// At least one should succeed, others might fail due to already closed servers
	var successCount int
	for err := range errorChan {
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

func TestGateway_gracefulShutdown_WithTCPProxy(t *testing.T) {
	tests := []struct {
		name           string
		setupGateway   func() *Gateway
		setupContext   func() (context.Context, context.CancelFunc)
		expectError    bool
		errorContains  string
		validateResult func(*testing.T, *Gateway)
	}{
		{
			name: "shutdown with TCP proxy and HTTP server",
			setupGateway: func() *Gateway {
				// Create a test TCP proxy
				tcpProxy := &tcp.Proxy{}

				// Create a test listener
				listener, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to create listener: %v", err)
				}

				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8080,
								protocol: "http",
								httpServer: &http.Server{
									Addr: ":8080",
								},
							},
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: tcpProxy,
								listener: listener,
							},
						},
						again: again.New(),
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
			name: "shutdown with TCP proxy only",
			setupGateway: func() *Gateway {
				// Create a test TCP proxy
				tcpProxy := &tcp.Proxy{}

				// Create a test listener
				listener, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to create listener: %v", err)
				}

				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: tcpProxy,
								listener: listener,
							},
						},
						again: again.New(),
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
			name: "shutdown with nil TCP proxy (should skip)",
			setupGateway: func() *Gateway {
				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: nil, // nil proxy should be skipped
								listener: nil,
							},
							{
								port:     8080,
								protocol: "http",
								httpServer: &http.Server{
									Addr: ":8080",
								},
							},
						},
						again: again.New(),
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
			name: "shutdown with nil listener (should skip)",
			setupGateway: func() *Gateway {
				tcpProxy := &tcp.Proxy{}

				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: tcpProxy,
								listener: nil, // nil listener should be skipped
							},
						},
						again: again.New(),
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
			name: "shutdown with timeout - TCP proxy",
			setupGateway: func() *Gateway {
				tcpProxy := &tcp.Proxy{}

				listener, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to create listener: %v", err)
				}

				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: tcpProxy,
								listener: listener,
							},
						},
						again: again.New(),
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
			name: "shutdown multiple TCP proxies",
			setupGateway: func() *Gateway {
				tcpProxy1 := &tcp.Proxy{}
				tcpProxy2 := &tcp.Proxy{}

				listener1, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to create listener1: %v", err)
				}

				listener2, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to create listener2: %v", err)
				}

				gw := &Gateway{
					DefaultProxyMux: &proxyMux{
						proxies: []*proxy{
							{
								port:     8443,
								protocol: "tcp",
								tcpProxy: tcpProxy1,
								listener: listener1,
							},
							{
								port:     8444,
								protocol: "tcp",
								tcpProxy: tcpProxy2,
								listener: listener2,
							},
						},
						again: again.New(),
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

func TestGateway_gracefulShutdown_TCPProxyWithActiveConnections(t *testing.T) {
	// Create a TCP proxy and listener
	tcpProxy := &tcp.Proxy{}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	gw := &Gateway{
		DefaultProxyMux: &proxyMux{
			proxies: []*proxy{
				{
					port:     listener.Addr().(*net.TCPAddr).Port,
					protocol: "tcp",
					tcpProxy: tcpProxy,
					listener: listener,
				},
			},
			again: again.New(),
		},
	}
	gw.SetConfig(config.Config{})
	gw.cacheCreate()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err = gw.gracefulShutdown(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected no error but got: %v", err)
	}

	// Should complete quickly since there are no active connections
	if elapsed > 1*time.Second {
		t.Errorf("shutdown took too long, expected less than 1s, got %v", elapsed)
	}
}

func TestGateway_gracefulShutdown_TCPProxyTimeout(t *testing.T) {
	// Create a TCP proxy and listener
	tcpProxy := &tcp.Proxy{}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	gw := &Gateway{
		DefaultProxyMux: &proxyMux{
			proxies: []*proxy{
				{
					port:     listener.Addr().(*net.TCPAddr).Port,
					protocol: "tcp",
					tcpProxy: tcpProxy,
					listener: listener,
				},
			},
			again: again.New(),
		},
	}
	gw.SetConfig(config.Config{})
	gw.cacheCreate()

	// Use a short timeout to test timeout handling
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = gw.gracefulShutdown(ctx)
	elapsed := time.Since(start)

	// Should not return an error even on timeout (it's handled gracefully)
	if err != nil {
		t.Errorf("expected no error but got: %v", err)
	}

	// Should complete quickly since there are no hanging connections to wait for
	if elapsed > 500*time.Millisecond {
		t.Errorf("shutdown took too long, expected less than 500ms, got %v", elapsed)
	}
}

func TestGateway_gracefulShutdown_MixedProxyConcurrency(t *testing.T) {
	// Test concurrent shutdown of multiple proxy types
	tcpProxy1 := &tcp.Proxy{}
	tcpProxy2 := &tcp.Proxy{}

	listener1, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener1: %v", err)
	}

	listener2, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener2: %v", err)
	}

	gw := &Gateway{
		DefaultProxyMux: &proxyMux{
			proxies: []*proxy{
				{
					port:     8080,
					protocol: "http",
					httpServer: &http.Server{
						Addr: ":8080",
					},
				},
				{
					port:     listener1.Addr().(*net.TCPAddr).Port,
					protocol: "tcp",
					tcpProxy: tcpProxy1,
					listener: listener1,
				},
				{
					port:     8081,
					protocol: "http",
					httpServer: &http.Server{
						Addr: ":8081",
					},
				},
				{
					port:     listener2.Addr().(*net.TCPAddr).Port,
					protocol: "tcp",
					tcpProxy: tcpProxy2,
					listener: listener2,
				},
			},
			again: again.New(),
		},
	}
	gw.SetConfig(config.Config{})
	gw.cacheCreate()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should handle mixed proxy types without issues
	err = gw.gracefulShutdown(ctx)
	if err != nil {
		t.Errorf("expected no error but got: %v", err)
	}
}

func TestLoadPoliciesFromRPC(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	prev := rpc.IsEmergencyMode()
	rpc.SetEmergencyMode(t, false)

	defer func() {
		rpc.SetEmergencyMode(t, prev)
	}()

	t.Run("responds error if failed to connect", func(t *testing.T) {
		store := policy.NewMockRPCDataLoader(gomock.NewController(t))
		store.EXPECT().Connect().Return(false)

		_, err := ts.Gw.LoadPoliciesFromRPC(store, "")

		assert.ErrorContains(t, err, "Failed connecting to database")
	})

	t.Run("responds with error if GetPolicies returns empty string", func(t *testing.T) {
		orgId := "org123"

		store := policy.NewMockRPCDataLoader(gomock.NewController(t))
		store.EXPECT().Connect().Return(true)
		store.EXPECT().GetPolicies(orgId).Return("")

		_, err := ts.Gw.LoadPoliciesFromRPC(store, orgId)

		assert.ErrorContains(t, err, "failed to fetch policies from RPC store; connection may be down")
	})

	t.Run("returns policies from rpc", func(t *testing.T) {
		mid := model.NewObjectID()

		var policies = []user.Policy{
			{MID: mid},
		}

		marshaledPolicies, err := json.Marshal(policies)
		assert.NoError(t, err)

		orgId := "org123"

		store := policy.NewMockRPCDataLoader(gomock.NewController(t))
		store.EXPECT().Connect().Return(true)
		store.EXPECT().GetPolicies(orgId).Return(string(marshaledPolicies))

		respondedPolicies, err := ts.Gw.LoadPoliciesFromRPC(store, orgId)
		assert.NoError(t, err)

		assert.Len(t, respondedPolicies, 1, "returns one policy like returned store")
		assert.Equal(t, mid.Hex(), respondedPolicies[mid.Hex()].ID, "ensures ID from MID ID is empty") // temporary solution can be removed in a while
	})

	t.Run("returns error if invalid policy received from rpc storage", func(t *testing.T) {
		var policies = []user.Policy{
			{MID: "invalid"},
		}

		marshaledPolicies, err := json.Marshal(policies)
		assert.NoError(t, err)

		orgId := "org123"

		store := policy.NewMockRPCDataLoader(gomock.NewController(t))
		store.EXPECT().Connect().Return(true)
		store.EXPECT().GetPolicies(orgId).Return(string(marshaledPolicies))

		_, err = ts.Gw.LoadPoliciesFromRPC(store, orgId)
		assert.ErrorContains(t, err, "invalid ObjectId in JSON")
	})
}

// TestDoReloadWithRetry_RetriesUntilSuccess verifies that DoReloadWithRetry keeps
// retrying when DoReloadWithError returns an error, and stops as soon as it succeeds.
// It also confirms that performedSuccessfulReload is true after recovery.
func TestDoReloadWithRetry_RetriesUntilSuccess(t *testing.T) {
	// Start without UseDBAppConfigs to avoid blocking in handleDashboardRegistration
	// during startup. We enable it and point at the mock after the gateway is up.
	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
	})
	defer ts.Close()

	// Use a fast retry interval so the test does not wait seconds between retries.
	ts.Gw.reloadRetryBackoff = func() backoff.BackOff {
		return backoff.NewConstantBackOff(50 * time.Millisecond)
	}

	const succeedOnCall = 3
	var callCount int

	// Mock dashboard: returns 500 for the first (succeedOnCall-1) calls, then 200.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/system/policies") || strings.Contains(r.URL.Path, "/system/apis") {
			callCount++
			if callCount < succeedOnCall {
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`{"Status":"Error","Message":"db unavailable","Meta":null}`))
				require.NoError(t, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/system/policies") {
				_, err := w.Write([]byte(`{"Message":[],"Nonce":"ok"}`))
				require.NoError(t, err)
			} else {
				_, err := w.Write([]byte(`{"Status":"OK","Nonce":"ok","Message":[]}`))
				require.NoError(t, err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Now enable dashboard mode and point at the mock.
	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DBAppConfOptions.ConnectionString = mockServer.URL
	conf.Policies.PolicySource = "service"
	conf.Policies.PolicyConnectionString = mockServer.URL
	ts.Gw.SetConfig(conf)

	ts.Gw.performedSuccessfulReload = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ts.Gw.DoReloadWithRetry(ctx)

	assert.True(t, ts.Gw.performedSuccessfulReload,
		"performedSuccessfulReload should be true after DoReloadWithRetry succeeds")
	assert.GreaterOrEqual(t, callCount, succeedOnCall,
		"mock should have been called at least %d times before succeeding", succeedOnCall)
}

// TestDoReloadWithRetry_StopsOnContextCancel verifies that DoReloadWithRetry exits
// cleanly when the context is cancelled, without blocking indefinitely.
func TestDoReloadWithRetry_StopsOnContextCancel(t *testing.T) {
	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
	})
	defer ts.Close()

	// Use a fast retry interval so context cancellation is observed quickly.
	ts.Gw.reloadRetryBackoff = func() backoff.BackOff {
		return backoff.NewConstantBackOff(50 * time.Millisecond)
	}

	// Mock dashboard that always returns 500 so the reload never succeeds.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(`{"Status":"Error","Message":"db unavailable","Meta":null}`))
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	// Enable dashboard mode after startup so handleDashboardRegistration does not block.
	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DBAppConfOptions.ConnectionString = mockServer.URL
	conf.Policies.PolicySource = "service"
	conf.Policies.PolicyConnectionString = mockServer.URL
	ts.Gw.SetConfig(conf)

	ts.Gw.performedSuccessfulReload = false

	// Cancel the context after a short window — the loop must exit within that window.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ts.Gw.DoReloadWithRetry(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Good — the loop exited after context cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("DoReloadWithRetry did not exit after context cancellation — goroutine leak suspected")
	}

	assert.False(t, ts.Gw.performedSuccessfulReload,
		"performedSuccessfulReload should remain false when reload never succeeded")
}

// TestDoReloadWithRetry_RetriesWithConstantInterval verifies that successive
// retry attempts are spaced by the configured interval. Uses a constant
// backoff so the test completes quickly with predictable timing.
func TestDoReloadWithRetry_RetriesWithConstantInterval(t *testing.T) {
	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
	})
	defer ts.Close()

	// Use a fast constant retry interval.
	ts.Gw.reloadRetryBackoff = func() backoff.BackOff {
		return backoff.NewConstantBackOff(100 * time.Millisecond)
	}

	const succeedOnCall = 4 // fail 3 times, succeed on the 4th
	var (
		mu        sync.Mutex
		callTimes []time.Time
		callCount int
	)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/system/policies") {
			mu.Lock()
			callCount++
			callTimes = append(callTimes, time.Now())
			n := callCount
			mu.Unlock()

			if n < succeedOnCall {
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`{"Status":"Error","Message":"db unavailable","Meta":null}`))
				require.NoError(t, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"Message":[],"Nonce":"ok"}`))
			require.NoError(t, err)
			return
		}
		if strings.Contains(r.URL.Path, "/system/apis") {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"Status":"OK","Nonce":"ok","Message":[]}`))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Enable dashboard mode after startup to avoid blocking in handleDashboardRegistration.
	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DBAppConfOptions.ConnectionString = mockServer.URL
	conf.Policies.PolicySource = "service"
	conf.Policies.PolicyConnectionString = mockServer.URL
	ts.Gw.SetConfig(conf)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ts.Gw.DoReloadWithRetry(ctx)

	mu.Lock()
	times := make([]time.Time, len(callTimes))
	copy(times, callTimes)
	mu.Unlock()

	require.GreaterOrEqual(t, len(times), succeedOnCall,
		"expected at least %d policy endpoint calls", succeedOnCall)

	// All intervals should be ~100ms (constant). Allow ±80ms tolerance for scheduler jitter.
	for i := 0; i < len(times)-1; i++ {
		actual := times[i+1].Sub(times[i])
		assert.InDelta(t, (100 * time.Millisecond).Milliseconds(), actual.Milliseconds(), 80,
			"interval between call %d and %d: got %v, want ~100ms", i+1, i+2, actual)
	}
}

// TestDoReload_RuntimeReloadLoopUnaffected verifies that the existing DoReload
// (used by reloadLoop at runtime) still returns without retrying on failure,
// keeping the hot-reload goroutine unblocked.
func TestDoReload_RuntimeReloadLoopUnaffected(t *testing.T) {
	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
	})
	defer ts.Close()

	// Note: no reloadRetryInterval override needed — DoReload does not use it.

	var callCount int
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(`{"Status":"Error","Message":"db unavailable","Meta":null}`))
		require.NoError(t, err)
	}))
	defer mockServer.Close()

	// Enable dashboard mode after startup to avoid blocking in handleDashboardRegistration.
	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DBAppConfOptions.ConnectionString = mockServer.URL
	conf.Policies.PolicySource = "service"
	conf.Policies.PolicyConnectionString = mockServer.URL
	ts.Gw.SetConfig(conf)

	// DoReload must return promptly even on failure — it must NOT retry.
	done := make(chan struct{})
	go func() {
		ts.Gw.DoReload()
		close(done)
	}()

	select {
	case <-done:
		// Good — returned without blocking.
	case <-time.After(5 * time.Second):
		t.Fatal("DoReload blocked unexpectedly — it must not retry")
	}

	// With RetryAttempts=0 it makes exactly 1 attempt (policies endpoint only,
	// since policies fail first and APIs are never reached).
	assert.Equal(t, 1, callCount,
		"DoReload should make exactly 1 request with RetryAttempts=0, got %d", callCount)
}

// TestRegister_DoReloadWithRetry_OnStartup verifies that when Register() is called
// and the initial DoReloadWithRetry fails (dashboard returns 500 for APIs/policies),
// the gateway keeps retrying until the upstream recovers, then marks the reload
// as successful — without re-registering the node.
func TestRegister_DoReloadWithRetry_OnStartup(t *testing.T) {
	const succeedOnCall = 3
	var (
		registerCount int
		policyCount   int
	)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/register/node"):
			registerCount++
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(NodeResponseOK{
				Status:  "ok",
				Message: map[string]string{"NodeID": "test-node-id"},
				Nonce:   fmt.Sprintf("nonce-%d", registerCount),
			})
			require.NoError(t, err)

		case strings.Contains(r.URL.Path, "/system/policies"):
			policyCount++
			if policyCount < succeedOnCall {
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`{"Status":"Error","Message":"db unavailable","Meta":null}`))
				require.NoError(t, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"Message":[],"Nonce":"ok"}`))
			require.NoError(t, err)

		case strings.Contains(r.URL.Path, "/system/apis"):
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"Status":"OK","Nonce":"ok","Message":[]}`))
			require.NoError(t, err)

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer mockServer.Close()

	// Start without UseDBAppConfigs to avoid blocking in handleDashboardRegistration.
	// We configure dashboard mode and point at the mock after the gateway is up.
	ts := StartTest(func(conf *config.Config) {
		conf.ResourceSync.RetryAttempts = 0
		conf.NodeSecret = "test-secret"
	})
	defer ts.Close()

	// Use a fast retry interval so retries happen in milliseconds during the test.
	ts.Gw.reloadRetryBackoff = func() backoff.BackOff {
		return backoff.NewConstantBackOff(50 * time.Millisecond)
	}

	// Enable dashboard mode and wire up the mock dashboard.
	conf := ts.Gw.GetConfig()
	conf.UseDBAppConfigs = true
	conf.DBAppConfOptions.ConnectionString = mockServer.URL
	conf.Policies.PolicySource = "service"
	conf.Policies.PolicyConnectionString = mockServer.URL
	ts.Gw.SetConfig(conf)

	ts.Gw.DashService = &HTTPDashboardHandler{
		Gw:                   ts.Gw,
		Secret:               "test-secret",
		RegistrationEndpoint: mockServer.URL + "/register/node",
	}
	ts.Gw.performedSuccessfulReload = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := ts.Gw.DashService.Register(ctx)

	assert.NoError(t, err, "Register should not return an error")
	assert.True(t, ts.Gw.performedSuccessfulReload,
		"performedSuccessfulReload should be true after recovery")
	assert.Equal(t, 1, registerCount,
		"/register/node must be called exactly once — DoReloadWithRetry must not re-register")
	assert.GreaterOrEqual(t, policyCount, succeedOnCall,
		"policy endpoint should have been retried at least %d times", succeedOnCall)
}
