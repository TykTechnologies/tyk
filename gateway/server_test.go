package gateway

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/user"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
				HealthCheckEndpointName: "hello",
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
				HealthCheckEndpointName: "hello",
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

			actual := ts.Gw.policiesByIDLen()

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

func TestGateway_getHostDetails(t *testing.T) {
	type checkFn func(*testing.T, *BufferedLogger, *Gateway)

	var (
		orig_readPIDFromFile = readPIDFromFile
		orig_mainLog         = mainLog
		bl                   = NewBufferingLogger()
		check                = func(fns ...checkFn) []checkFn { return fns }

		hasErr = func(wantErr bool, errorText string) checkFn {
			return func(t *testing.T, bl *BufferedLogger, gw *Gateway) {
				logs := bl.GetLogs(logrus.ErrorLevel)
				if !wantErr && assert.Empty(t, logs) {
					return
				}

				if wantErr && !assert.NotEmpty(t, logs) {
					return
				}

				if wantErr && errorText != "" {
					for _, log := range logs {
						assert.Contains(t, log.Message, errorText)
					}
				}
			}
		}

		hasAddress = func(addr string) checkFn {
			return func(t *testing.T, bl *BufferedLogger, gw *Gateway) {
				matched, err := regexp.MatchString(addr, gw.hostDetails.Address)
				if err != nil {
					t.Errorf("Failed to compile regex pattern: %v", err)
				}
				if !matched {
					t.Errorf("Wanted address %s, got %s", addr, gw.hostDetails.Address)
				}
			}
		}
	)

	// replace the logger with a mock to capture the errors
	mainLog = bl.Logger.WithField("prefix", "test")

	// get back the original functions
	defer func() {
		readPIDFromFile = orig_readPIDFromFile
		mainLog = orig_mainLog
	}()

	tests := []struct {
		name            string
		before          func(*Gateway)
		readPIDFromFile func(string) (int, error)
		checks          []checkFn
	}{
		// {
		// 	name:            "fail-read-pid",
		// 	readPIDFromFile: func(file string) (int, error) { return 0, fmt.Errorf("Error opening file") },
		// 	before: func(gw *Gateway) {
		// 		gw.SetConfig(config.Config{
		// 			ListenAddress: "127.0.0.1",
		// 		})
		// 	},
		// 	checks: check(
		// 		hasErr(true, "Error opening file"),
		// 	),
		// },
		{
			name:            "success-listen-address-exists",
			readPIDFromFile: func(file string) (int, error) { return 1000, nil },
			before: func(gw *Gateway) {
				gw.SetConfig(config.Config{
					ListenAddress: "127.0.0.1",
				})
			},
			checks: check(
				hasErr(false, ""),
				hasAddress("127.0.0.1"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readPIDFromFile = tt.readPIDFromFile
			gw := &Gateway{}

			if tt.before != nil {
				tt.before(gw)
			}

			// gw.SetConfig(config.Config{
			// 	PIDFileLocation: "./test.pid",
			// })

			// ts := StartTest(tt.before)
			// defer ts.Close()

			gw.getHostDetails(gw.GetConfig().PIDFileLocation)
			for _, c := range tt.checks {
				c(t, bl, gw)
			}
		})
	}
}
