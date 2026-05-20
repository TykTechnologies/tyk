package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	tykregexp "github.com/TykTechnologies/tyk/regexp"
)

// T7
func TestGateway_afterConfSetup_RegexpCache(t *testing.T) {
	t.Cleanup(func() {
		// Restore package defaults for other tests in the binary.
		tykregexp.Configure(tykregexp.CacheOptions{Enabled: true})
	})

	t.Run("MaxEntries_zero_uses_default", func(t *testing.T) {
		gw := NewGateway(config.Config{}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		for i := 0; i < 5001; i++ {
			_, _ = tykregexp.Compile(fmt.Sprintf("^t7-default-%d-.*$", i))
		}
		assert.Equal(t, 5000, tykregexp.CompileCacheLen(),
			"MaxEntries=0 should select default cap of 5000")
	})

	t.Run("MaxEntries_100_enforces_cap", func(t *testing.T) {
		gw := NewGateway(config.Config{RegexpCacheMaxEntries: 100}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		for i := 0; i < 101; i++ {
			_, _ = tykregexp.Compile(fmt.Sprintf("^t7-100-%d-.*$", i))
		}
		assert.Equal(t, 100, tykregexp.CompileCacheLen(),
			"MaxEntries=100 should cap the cache at 100 entries")
	})

	t.Run("MaxEntries_negative_unbounded", func(t *testing.T) {
		gw := NewGateway(config.Config{RegexpCacheMaxEntries: -1}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		const n = 5001
		for i := 0; i < n; i++ {
			_, _ = tykregexp.Compile(fmt.Sprintf("^t7-neg-%d-.*$", i))
		}
		assert.Equal(t, n, tykregexp.CompileCacheLen(),
			"MaxEntries<0 should disable size eviction")
	})

	t.Run("RegexpCacheExpire_drives_TTL_eviction", func(t *testing.T) {
		if testing.Short() {
			t.Skip("ttl eviction requires a wall-clock sleep; skip in -short")
		}
		gw := NewGateway(config.Config{
			RegexpCacheExpire:     1,
			RegexpCacheMaxEntries: 100,
		}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		_, err := tykregexp.Compile("^t8-ttl-victim.*$")
		require.NoError(t, err)
		require.Equal(t, 1, tykregexp.CompileCacheLen(),
			"entry should be present immediately after Compile")

		time.Sleep(1500 * time.Millisecond)

		assert.Equal(t, 0, tykregexp.CompileCacheLen(),
			"RegexpCacheExpire=1s should evict after 1.5s")
	})
}

// T8c — warning log fires when RegexpCacheMaxEntries is negative.
func TestAfterConfSetup_WarnsOnNegativeMaxEntries(t *testing.T) {
	t.Cleanup(func() {
		tykregexp.Configure(tykregexp.CacheOptions{Enabled: true})
	})

	hook := &logrustest.Hook{}
	log.AddHook(hook)
	defer log.ReplaceHooks(make(logrus.LevelHooks))

	gw := NewGateway(config.Config{RegexpCacheMaxEntries: -1}, context.Background())
	require.NoError(t, gw.afterConfSetup())

	var found bool
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "size eviction disabled") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected warning log about disabled size eviction")
}
