package log

import (
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockHook struct{}

func (m *mockHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (m *mockHook) Fire(_ *logrus.Entry) error {
	return nil
}

type mockSink struct {
	Sinker
}

func TestBuilder(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		b := &Builder{}
		logger := b.BuildAndPropagate()

		assert.NotNil(t, logger)
		assert.Equal(t, io.Discard, logger.Out)
		assert.IsType(t, &dummyFormatter{}, logger.Formatter)
		assert.Empty(t, logger.Hooks)
	})

	t.Run("WithLevel", func(t *testing.T) {
		b := &Builder{}
		b.WithLevel(logrus.DebugLevel)
		logger := b.BuildAndPropagate()

		assert.Equal(t, logrus.DebugLevel, logger.Level)
	})

	t.Run("WithDiscardOutput", func(t *testing.T) {
		b := &Builder{}
		b.AddSink(&mockSink{})
		b.WithDiscardOutput()

		logger := b.BuildAndPropagate()

		assert.Empty(t, logger.Hooks)
	})

	t.Run("AddSink", func(t *testing.T) {
		b := &Builder{}
		b.AddSink(&mockSink{})
		logger := b.BuildAndPropagate()

		assert.NotEmpty(t, logger.Hooks)

		registeredHooks := logger.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &multiSinkHook{}, registeredHooks[0])
	})

	t.Run("AddHook", func(t *testing.T) {
		b := &Builder{}
		customHook := &mockHook{}
		b.AddHook(customHook)

		logger := b.BuildAndPropagate()

		registeredHooks := logger.Hooks[logrus.InfoLevel]

		found := false
		for _, h := range registeredHooks {
			if _, ok := h.(*mockHook); ok {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("WithPropagate", func(t *testing.T) {
		stdLogger := logrus.New()
		stdLogger.SetLevel(logrus.FatalLevel)
		stdLogger.SetOutput(io.Discard)

		b := &Builder{}
		b.WithStdLog(stdLogger)
		b.WithLevel(logrus.TraceLevel)
		b.AddSink(&mockSink{})
		b.WithPropagate()

		logger := b.BuildAndPropagate()

		assert.Equal(t, logrus.TraceLevel, logger.Level)
		assert.Equal(t, logrus.TraceLevel, stdLogger.Level)
		assert.Equal(t, io.Discard, stdLogger.Out)
		assert.IsType(t, &dummyFormatter{}, stdLogger.Formatter)

		registeredHooks := stdLogger.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &multiSinkHook{}, registeredHooks[0])
	})

	t.Run("WithPropagate_DiscardOutput", func(t *testing.T) {
		stdLogger := logrus.New()

		b := &Builder{}
		b.WithStdLog(stdLogger)
		b.WithPropagate()
		b.AddSink(&mockSink{})
		b.WithDiscardOutput()

		b.BuildAndPropagate()

		assert.Empty(t, stdLogger.Hooks)
	})

	t.Run("WithApplyHooksToRawLog_Enabled", func(t *testing.T) {
		b := &Builder{}
		rawLogger := logrus.New()
		customHook := &mockHook{}

		b.WithRawLog(rawLogger)
		b.AddHook(customHook)
		b.WithApplyHooksToRawLog()

		b.BuildAndPropagate()

		assert.NotEmpty(t, rawLogger.Hooks)
		registeredHooks := rawLogger.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &mockHook{}, registeredHooks[0])
	})

	t.Run("WithApplyHooksToRawLog_Disabled", func(t *testing.T) {
		b := &Builder{}
		rawLogger := logrus.New()
		customHook := &mockHook{}

		b.WithRawLog(rawLogger)
		b.AddHook(customHook)

		b.BuildAndPropagate()

		assert.Empty(t, rawLogger.Hooks)
	})

	t.Run("WithApplyHooksToRawLog_DefaultGlobalRawLog", func(t *testing.T) {
		originalRawLogHooks := make(logrus.LevelHooks)
		for k, v := range rawLog.Hooks {
			originalRawLogHooks[k] = v
		}
		defer func() {
			rawLog.Hooks = originalRawLogHooks
		}()

		rawLog.Hooks = make(logrus.LevelHooks)

		b := &Builder{}
		customHook := &mockHook{}

		b.AddHook(customHook)
		b.WithApplyHooksToRawLog()

		b.BuildAndPropagate()

		assert.NotEmpty(t, rawLog.Hooks)
		registeredHooks := rawLog.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &mockHook{}, registeredHooks[0])
	})
}

func TestDummyFormatter(t *testing.T) {
	t.Run("Format", func(t *testing.T) {
		formatter := &dummyFormatter{}

		bytes, err := formatter.Format(&logrus.Entry{Message: "test"})

		assert.NoError(t, err)
		assert.Nil(t, bytes)
	})
}
