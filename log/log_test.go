package log

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
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

func Test_Logger(t *testing.T) {
	makeDummySink := func(writer io.Writer) Sinker {
		return NewSink(writer, &logrus.TextFormatter{}, AcceptorAllowAll)
	}

	t.Run("Setup", func(t *testing.T) {
		t.Run("flushes setup", func(t *testing.T) {
			buf := &bytes.Buffer{}

			lgr := New()
			lgr.Info("pre-setup log")

			assert.Len(t, lgr.tmpLogsCollector.entries, 1)
			lgr.Setup(func(b *Builder) {
				b.AddSink(makeDummySink(buf))
			})

			assert.Empty(t, lgr.tmpLogsCollector.entries)
			assert.Contains(t, buf.String(), "pre-setup log")
		})

		t.Run("panics if called twice", func(t *testing.T) {
			lgr := New()
			lgr.Setup(func(_ *Builder) {})

			assert.Panics(t, func() {
				lgr.Setup(func(_ *Builder) {})
			})
		})
	})

	t.Run("flushes to emergency logger if setup was not called", func(t *testing.T) {
		buf := bytes.Buffer{}

		lgr := New()
		lgr.emergencyLogger.SetOutput(&buf)

		lgr.Info("fatal startup error")
		assert.Len(t, lgr.tmpLogsCollector.entries, 1)

		lgr.Flush()

		assert.Empty(t, lgr.tmpLogsCollector.entries)
		assert.Contains(t, buf.String(), "fatal startup error")
	})

	t.Run("Flush", func(t *testing.T) {
		t.Run("does not add logs to output", func(t *testing.T) {
			lgr := New()
			emBuf := &bytes.Buffer{}
			lgr.emergencyLogger.SetOutput(emBuf)

			lgr.Setup(func(_ *Builder) {})

			log.Info("post-setup log")
			lgr.Flush()

			assert.Empty(t, emBuf.String())
		})
	})

	t.Run("RemoveHook", func(t *testing.T) {
		t.Run("removes hook", func(t *testing.T) {
			logger := New()
			logger.ReplaceHooks(make(logrus.LevelHooks))

			hook := &logrustest.Hook{}
			logger.AddHook(hook)

			for _, hooks := range logger.Hooks {
				assert.True(t, len(hooks) == 1, "each logger level hes it's hook")
			}

			logger.RemoveHook(hook)

			for _, hooks := range logger.Hooks {
				assert.True(t, len(hooks) == 0, "has removed all the hooks from logger")
			}
		})
	})
}

func TestGetAndGetRaw(t *testing.T) {
	logger := Get()
	assert.NotNil(t, logger)
	assert.Equal(t, log, logger)

	rawLogger := GetRaw()
	assert.NotNil(t, rawLogger)
	assert.Equal(t, rawLog, rawLogger)
}

func Test_Logger_IsLegacyFormatter(t *testing.T) {
	for _, tc := range []struct {
		name           string
		format         Format
		expectedResult bool
	}{
		{"text", FormatText, false},
		{"json", FormatJson, false},
		{"legacy", FormatLegacy, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lgr := New()
			lgr.Setup(func(b *Builder) {
				b.SetLegacyLogformat(tc.format == FormatLegacy)
			})

			assert.Equal(t, tc.expectedResult, lgr.IsLegacyFormatter())
		})
	}
}
