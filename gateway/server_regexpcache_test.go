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

	t.Run("DisableRegexpCacheBound_unbounded", func(t *testing.T) {
		gw := NewGateway(config.Config{DisableRegexpCacheBound: true}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		const n = 5001
		for i := 0; i < n; i++ {
			_, _ = tykregexp.Compile(fmt.Sprintf("^t7-unbnd-%d-.*$", i))
		}
		assert.Equal(t, n, tykregexp.CompileCacheLen(),
			"DisableRegexpCacheBound=true should disable size eviction")
	})

	t.Run("Negative_MaxEntries_clamped_to_default", func(t *testing.T) {
		gw := NewGateway(config.Config{RegexpCacheMaxEntries: -1}, context.Background())
		require.NoError(t, gw.afterConfSetup())

		for i := 0; i < 5001; i++ {
			_, _ = tykregexp.Compile(fmt.Sprintf("^t7-neg-%d-.*$", i))
		}
		assert.Equal(t, 5000, tykregexp.CompileCacheLen(),
			"negative MaxEntries (without DisableRegexpCacheBound) should fall back to the default cap")
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
		// Force lazy expiration: the Get path drops expired entries
		// deterministically, while Len() reflects only what the bucket
		// sweeper has already reaped.
		_, _ = tykregexp.Compile("^t8-ttl-victim.*$")

		assert.Equal(t, 1, tykregexp.CompileCacheLen(),
			"after TTL expiry, only the freshly-recompiled entry should remain")
	})
}

// T8c — warning log fires when DisableRegexpCacheBound is set.
func TestAfterConfSetup_WarnsOnDisableRegexpCacheBound(t *testing.T) {
	t.Cleanup(func() {
		tykregexp.Configure(tykregexp.CacheOptions{Enabled: true})
	})

	hook := &logrustest.Hook{}
	log.AddHook(hook)
	defer log.ReplaceHooks(make(logrus.LevelHooks))

	gw := NewGateway(config.Config{DisableRegexpCacheBound: true}, context.Background())
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

// T8d — warning log fires when RegexpCacheMaxEntries is negative
// (deprecation path that points users to DisableRegexpCacheBound).
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
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "is invalid") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected warning log pointing at DisableRegexpCacheBound")
}
