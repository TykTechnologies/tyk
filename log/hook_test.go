package log

import (
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func Test_Hook(t *testing.T) {
	t.Run("NewHook", func(t *testing.T) {
		t.Run("creates internal hook if not provided", func(t *testing.T) {
			hook := NewHook(nil)
			assert.NotNil(t, hook.locaHookAlias)
		})

		t.Run("wraps hooks", func(t *testing.T) {
			rawHook := new(logrustest.Hook)
			hook := NewHook(rawHook)
			assert.NotNil(t, hook.locaHookAlias)
			assert.Same(t, rawHook, hook.locaHookAlias)
		})
	})

	t.Run("SomeBy_FilterBy_CountBy", func(t *testing.T) {
		logger, raw := logrustest.NewNullLogger()
		logger.Warning("test log")
		logger.Info("info log")
		logger.Info("info log")

		hook := NewHook(raw)

		predicateBy := func(level logrus.Level) func(entry *logrus.Entry) bool {
			return func(entry *logrus.Entry) bool {
				return entry.Level == level
			}
		}

		predicateWarnLevel := predicateBy(logrus.WarnLevel)
		predicateInfoLevel := predicateBy(logrus.InfoLevel)
		predicateErrorLevel := predicateBy(logrus.ErrorLevel)

		assert.True(t, hook.SomeBy(predicateWarnLevel))
		assert.Equal(t, 1, hook.CountBy(predicateWarnLevel))
		assert.Len(t, hook.FilterBy(predicateWarnLevel), 1)

		assert.True(t, hook.SomeBy(predicateInfoLevel))
		assert.Equal(t, 2, hook.CountBy(predicateInfoLevel))
		assert.Len(t, hook.FilterBy(predicateInfoLevel), 2)

		assert.False(t, hook.SomeBy(predicateErrorLevel))
		assert.Equal(t, 0, hook.CountBy(predicateErrorLevel))
		assert.Len(t, hook.FilterBy(predicateErrorLevel), 0)
	})
}
