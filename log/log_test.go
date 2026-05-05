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

func Test_SetupFormatter(t *testing.T) {
	resetLogger := func(t *testing.T) {
		t.Helper()

		tykFormatter := log.Formatter
		globalFormatter := logrus.StandardLogger().Formatter

		log.Formatter = nil
		logrus.StandardLogger().Formatter = nil

		t.Cleanup(func() {
			log.Formatter = tykFormatter
			logrus.StandardLogger().Formatter = globalFormatter
		})
	}

	type Formatters struct {
		tyk logrus.Formatter
		std logrus.Formatter
	}

	formatters := func(t *testing.T) Formatters {
		t.Helper()

		return Formatters{
			std: logrus.StandardLogger().Formatter,
			tyk: log.Formatter,
		}
	}

	t.Run("empty or unknown or text value sets default text formatter; global tyk and global logrus formatters", func(t *testing.T) {
		t.Run("empty", func(t *testing.T) {
			resetLogger(t)
			SetupFormatter("")
			f := formatters(t)
			assert.Same(t, f.tyk, f.std)
			assert.NotNil(t, f.std)
			assert.NotNil(t, f.tyk)
			assert.Equal(t, newFormatterText(), f.tyk)
		})

		t.Run("any other", func(t *testing.T) {
			resetLogger(t)
			SetupFormatter("hwdp")
			f := formatters(t)
			assert.Same(t, f.tyk, f.std)
			assert.NotNil(t, f.std)
			assert.NotNil(t, f.tyk)
			assert.Equal(t, newFormatterText(), f.tyk)
		})

		t.Run("text", func(t *testing.T) {
			resetLogger(t)
			SetupFormatter(FormatText)
			f := formatters(t)
			assert.Same(t, f.tyk, f.std)
			assert.NotNil(t, f.std)
			assert.NotNil(t, f.tyk)
			assert.Equal(t, newFormatterText(), f.tyk)
		})
	})

	t.Run("json formatter", func(t *testing.T) {
		resetLogger(t)
		SetupFormatter(FormatJson)
		f := formatters(t)
		assert.Same(t, f.tyk, f.std)
		assert.NotNil(t, f.std)
		assert.NotNil(t, f.tyk)
		assert.Equal(t, newFormatterJson(), f.tyk)
	})

	t.Run("legacy formatter does not modify std logrus formatter", func(t *testing.T) {
		resetLogger(t)
		SetupFormatter(FormatLegacy)
		f := formatters(t)
		assert.Nil(t, f.std)    // does not set formatter for std logger
		assert.NotNil(t, f.tyk) // does not set formatter for std logger
		assert.Equal(t, newFormatterLegacy(), f.tyk)
	})
}

type testFormatter struct{}

func (*testFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

func BenchmarkFormatter(b *testing.B) {
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

func benchmarkFormatter(b *testing.B, formatter logrus.Formatter) {
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
