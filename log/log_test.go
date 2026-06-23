package log

import (
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
				b.SetLogformat(tc.format)
			})

			assert.Equal(t, tc.expectedResult, lgr.IsLegacyFormatterEnabled())
		})
	}
}
