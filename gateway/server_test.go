package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := NewGateway(tt.initialConfig, context.Background())
			gw.afterConfSetup()

			assert.Equal(t, tt.expectedConfig, gw.GetConfig())

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
