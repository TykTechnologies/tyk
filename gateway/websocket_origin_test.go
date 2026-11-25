package gateway

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestAfterConfSetup_WarnsWhenWebSocketOriginCheckIsOff(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	hook := log.GetTestHook(t)

	warned := func() bool {
		return hook.SomeBy(func(entry *logrus.Entry) bool {
			return entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "allow_unsafe_websocket_origin")
		})
	}

	t.Run("off by default, no warning", func(t *testing.T) {
		require.NoError(t, ts.Gw.afterConfSetup())
		assert.False(t, ts.Gw.GetConfig().AllowUnsafeWebSocketOrigin)
		assert.False(t, warned())
	})

	t.Run("on, warning logged", func(t *testing.T) {
		ts.Gw.SetConfig(func() config.Config {
			conf := ts.Gw.GetConfig()
			conf.AllowUnsafeWebSocketOrigin = true
			return conf
		}())
		require.NoError(t, ts.Gw.afterConfSetup())
		assert.True(t, warned())
	})
}
