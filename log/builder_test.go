package log

import (
	"bytes"
	"io"
	stdlog "log"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockHook struct{}

func (m *mockHook) Levels() []logrus.Level     { return logrus.AllLevels }
func (m *mockHook) Fire(_ *logrus.Entry) error { return nil }

type mockSink struct{}

func (m *mockSink) Sink(_ *logrus.Entry) {}

func TestBuilder(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		logger := Build(func(_ *Builder) {})

		assert.NotNil(t, logger)
		assert.Equal(t, io.Discard, logger.Out)
		assert.IsType(t, &dummyFormatter{}, logger.Formatter)
		assert.Empty(t, logger.Hooks)
	})

	t.Run("WithDiscardOutput", func(t *testing.T) {
		logger := Build(func(b *Builder) {
			b.AddSinker(&mockSink{})
			b.WithDiscardOutput()
		})

		assert.Empty(t, logger.Hooks, "skips writing to all sinks; and does not add multi sink-hook")
	})

	t.Run("AddSink", func(t *testing.T) {
		logger := Build(func(b *Builder) {
			b.AddSinker(&mockSink{})
		})

		assert.NotEmpty(t, logger.Hooks)

		registeredHooks := logger.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &multiSinkHook{}, registeredHooks[0])
	})

	t.Run("AddHook", func(t *testing.T) {
		customHook := &mockHook{}

		logger := Build(func(b *Builder) {
			b.AddHook(customHook)
		})

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

	t.Run("WithLevel sets the generated level and leaves sink ranges alone", func(t *testing.T) {
		buf := &bytes.Buffer{}
		sink := NewSink(buf, &mockFormatter{}, NewAcceptorRange(logrus.DebugLevel, logrus.InfoLevel))

		logger := Build(func(b *Builder) {
			b.WithLevel(logrus.InfoLevel)
			b.AddSinker(sink)
		})

		assert.Equal(t, logrus.InfoLevel, logger.GetLevel())

		logger.Debug("dropped by level")
		logger.Info("written")
		logger.Warn("dropped by sink range")
		assert.Equal(t, "written", buf.String())
	})

	t.Run("RedirectStdlib", func(t *testing.T) {
		goLog := stdlog.New(io.Discard, "", stdlog.LstdFlags)

		logger := Build(func(b *Builder) {
			b.WithLevel(logrus.InfoLevel)
			b.WithStdlibLogger(goLog)
			b.RedirectStdlib(logrus.WarnLevel)
		})
		hook := logger.GetTestHook(t)

		goLog.Print("http: TLS handshake error from 10.0.0.1: EOF")

		assert.Equal(t, 0, goLog.Flags(), "stdlib timestamp disabled")
		if assert.Len(t, hook.AllEntries(), 1) {
			entry := hook.LastEntry()
			assert.Equal(t, logrus.WarnLevel, entry.Level)
			assert.Equal(t, "http: TLS handshake error from 10.0.0.1: EOF", entry.Message)
			assert.Equal(t, "stdlib", entry.Data["prefix"])
		}
	})

	t.Run("RedirectStdlib not requested leaves the standard logger alone", func(t *testing.T) {
		goLog := stdlog.New(io.Discard, "", stdlog.LstdFlags)

		_ = Build(func(b *Builder) {
			b.WithStdlibLogger(goLog)
		})

		assert.Equal(t, stdlog.LstdFlags, goLog.Flags())
	})

	t.Run("WithPropagate", func(t *testing.T) {
		stdLogger := logrus.New()
		stdLogger.SetLevel(logrus.FatalLevel)
		stdLogger.SetOutput(io.Discard)

		_ = Build(func(b *Builder) {
			b.WithStdLog(stdLogger)
			b.WithLevel(logrus.TraceLevel)
			b.AddSinker(&mockSink{})
			b.WithPropagate()
		})

		assert.Equal(t, io.Discard, stdLogger.Out)
		assert.IsType(t, &dummyFormatter{}, stdLogger.Formatter)

		registeredHooks := stdLogger.Hooks[logrus.InfoLevel]
		assert.Len(t, registeredHooks, 1)
		assert.IsType(t, &multiSinkHook{}, registeredHooks[0])
	})

	t.Run("WithPropagate_DiscardOutput", func(t *testing.T) {
		stdLogger := logrus.New()
		_ = Build(func(b *Builder) {
			b.WithStdLog(stdLogger)
			b.WithPropagate()
			b.AddSinker(&mockSink{})
			b.WithDiscardOutput()
		})

		assert.Empty(t, stdLogger.Hooks)
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
