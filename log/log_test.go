package log

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewFormatter(t *testing.T) {
	for _, typ := range []string{"text", "any_other_is_default", ""} {
		textFormatter, ok := NewFormatter(Format(typ)).(*logrus.TextFormatter)
		assert.NotNil(t, textFormatter)
		assert.True(t, ok)
		assert.Equal(t, time.RFC3339, textFormatter.TimestampFormat)
	}

	jsonFormatter, ok := NewFormatter("json").(*JSONFormatter)
	assert.NotNil(t, jsonFormatter)
	assert.True(t, ok)
	assert.Equal(t, time.RFC3339, jsonFormatter.TimestampFormat)

	legacyFormatter, ok := NewFormatter("legacy").(*logrus.TextFormatter)
	assert.True(t, ok)
	assert.NotNil(t, legacyFormatter)
	assert.Equal(t, LegacyTimestampFormat, legacyFormatter.TimestampFormat)
	assert.True(t, legacyFormatter.FullTimestamp)
	assert.True(t, legacyFormatter.DisableColors)
	assert.True(t, isLegacyFormatter(legacyFormatter))
}

type testFormatter struct{}

func (*testFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

func BenchmarkFormatter(b *testing.B) {
	benchmarkFormatter := func(b *testing.B, formatter logrus.Formatter) {
		b.Helper()

		logger := logrus.New()
		logger.Out = io.Discard
		logger.Formatter = formatter

		err := errors.New("Test error value")

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i <= b.N; i++ {
			logger.WithError(err).WithField("prefix", "test").Info("This is a typical log message")
		}
	}

	b.Run("json", func(b *testing.B) {
		benchmarkFormatter(b, newFormatterJson())
	})
	b.Run("json-logrus", func(b *testing.B) {
		benchmarkFormatter(b, newFormatterLogrusJson())
	})
	b.Run("text/default", func(b *testing.B) {
		benchmarkFormatter(b, newFormatterText())
	})
	b.Run("none", func(b *testing.B) {
		benchmarkFormatter(b, &testFormatter{})
	})
}

func TestJSONFormatterErrorHandling(t *testing.T) {
	formatter := &JSONFormatter{
		TimestampFormat: time.RFC3339,
	}

	t.Run("error type in error key", func(t *testing.T) {
		entry := &logrus.Entry{
			Data: logrus.Fields{
				logrus.ErrorKey: errors.New("test error"),
			},
			Time:    time.Now(),
			Level:   logrus.InfoLevel,
			Message: "test message",
		}

		output, err := formatter.Format(entry)
		assert.NoError(t, err)
		assert.Contains(t, string(output), `"logrus_error":"test error"`)
	})

	t.Run("non-error type in error key", func(t *testing.T) {
		entry := &logrus.Entry{
			Data: logrus.Fields{
				logrus.ErrorKey: "string error",
			},
			Time:    time.Now(),
			Level:   logrus.InfoLevel,
			Message: "test message",
		}

		output, err := formatter.Format(entry)
		assert.NoError(t, err)
		assert.Contains(t, string(output), `"logrus_error":"string error"`)
	})

	t.Run("no error key present", func(t *testing.T) {
		entry := &logrus.Entry{
			Data:    logrus.Fields{},
			Time:    time.Now(),
			Level:   logrus.InfoLevel,
			Message: "test message",
		}

		output, err := formatter.Format(entry)
		assert.NoError(t, err)
		assert.NotContains(t, string(output), "logrus_error")
	})
}

func resetState(t *testing.T, emOut io.Writer) {
	t.Helper()

	cancel := once.reset(false)
	t.Cleanup(cancel)

	tmpLoggerHook = &tmpLogsCollector{}

	tmpLogger = logrus.New()
	tmpLogger.SetOutput(io.Discard)
	tmpLogger.AddHook(tmpLoggerHook)

	log = &loggerWrapper{Logger: tmpLogger}

	emergencyLogger = logrus.New()
	emergencyLogger.SetOutput(emOut)
	emergencyLogger.SetFormatter(&RawFormatter{})
}

func TestSetup_ExecutionAndProxy(t *testing.T) {
	resetState(t, io.Discard)

	log.Info("pre-setup log")
	assert.Len(t, tmpLoggerHook.entries, 1)

	Setup(func(_ *Builder) {})

	assert.Empty(t, tmpLoggerHook.entries)
	assert.NotEqual(t, tmpLogger, log.Logger)
}

func TestSetup_PanicsOnMultipleCalls(t *testing.T) {
	resetState(t, io.Discard)

	Setup(func(_ *Builder) {})

	assert.Panics(t, func() {
		Setup(func(_ *Builder) {})
	})
}

func TestFlush_WithoutSetup(t *testing.T) {
	emBuf := &bytes.Buffer{}
	resetState(t, emBuf)

	log.Info("fatal startup error")
	assert.Len(t, tmpLoggerHook.entries, 1)

	Flush()

	assert.Empty(t, tmpLoggerHook.entries)
	assert.Contains(t, emBuf.String(), "fatal startup error")
}

func TestFlush_AfterSetup(t *testing.T) {
	emBuf := &bytes.Buffer{}
	resetState(t, emBuf)

	Setup(func(_ *Builder) {})

	log.Info("post-setup log")

	Flush()

	assert.Empty(t, emBuf.String())
}

func TestGetAndGetRaw(t *testing.T) {
	resetState(t, io.Discard)

	logger := Get()
	assert.NotNil(t, logger)
	assert.Equal(t, log, logger)

	rawLogger := GetRaw()
	assert.NotNil(t, rawLogger)
	assert.Equal(t, rawLog, rawLogger)
}

func TestIsLegacyFormatter(t *testing.T) {
	legacyFmt := newFormatterLegacy()
	assert.True(t, isLegacyFormatter(legacyFmt))

	textFmt := newFormatterText()
	assert.False(t, isLegacyFormatter(textFmt))

	jsonFmt := newFormatterJson()
	assert.False(t, isLegacyFormatter(jsonFmt))
}

func TestWrap(t *testing.T) {
	l := logrus.New()
	wrapped := Wrap(l)

	assert.NotNil(t, wrapped)
	assert.Equal(t, l, wrapped.AsLogrus())
}

func Test_removeHook(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	hook := &logrustest.Hook{}
	logger.AddHook(hook)

	for _, hooks := range logger.Hooks {
		assert.True(t, len(hooks) == 1, "each logger level hes it's hook")
	}

	removeHook(logger, hook)

	for _, hooks := range logger.Hooks {
		assert.True(t, len(hooks) == 0, "has removed all the hooks from logger")
	}
}
