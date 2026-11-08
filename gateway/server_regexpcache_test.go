package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	tykregexp "github.com/TykTechnologies/tyk/regexp"
)

// TestAfterConfSetup_WarnsOnDisableRegexpCacheBound verifies that a
// warning log fires when DisableRegexpCacheBound is set.
func TestAfterConfSetup_WarnsOnDisableRegexpCacheBound(t *testing.T) {
	t.Cleanup(func() {
		tykregexp.Configure(tykregexp.CacheOptions{Enabled: true})
	})

	hook := log.GetTestHook(t)

	gw := NewGateway(config.Config{DisableRegexpCacheBound: true}, t.Context())
	require.NoError(t, gw.afterConfSetup())

	found := hook.SomeBy(func(e *logrus.Entry) bool {
		return e.Level == logrus.WarnLevel && strings.Contains(e.Message, "size eviction disabled")
	})

	assert.True(t, found, "expected warning log about disabled size eviction")
}

// TestAfterConfSetup_WarnsOnNegativeMaxEntries verifies that a warning
// log fires when RegexpCacheMaxEntries is negative (deprecation path
// pointing users to DisableRegexpCacheBound).
func TestAfterConfSetup_WarnsOnNegativeMaxEntries(t *testing.T) {
	t.Cleanup(func() {
		tykregexp.Configure(tykregexp.CacheOptions{Enabled: true})
	})

	hook := log.GetTestHook(t)

	gw := NewGateway(config.Config{RegexpCacheMaxEntries: -1}, context.Background())
	require.NoError(t, gw.afterConfSetup())

	found := hook.SomeBy(func(e *logrus.Entry) bool {
		return e.Level == logrus.WarnLevel && strings.Contains(e.Message, "is invalid")
	})

	assert.True(t, found, "expected warning log pointing at DisableRegexpCacheBound")
}
