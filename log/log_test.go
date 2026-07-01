package log

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	// json-logrus is added for benchmarks
	formatterIndex["json-logrus"] = func() logrus.Formatter {
		return &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		}
	}
}

// Verifies: STK-REQ-088, SYS-REQ-176, SW-REQ-163
// STK-REQ-088:STK-REQ-088-AC-01:acceptance
// SW-REQ-163:nominal:nominal
// SW-REQ-163:boundary:nominal
// SW-REQ-163:determinism:nominal
func TestNewFormatter(t *testing.T) {
	textFormatter, ok := NewFormatter("").(*logrus.TextFormatter)
	assert.NotNil(t, textFormatter)
	assert.True(t, ok)

	jsonFormatter, ok := NewFormatter("json").(*JSONFormatter)
	assert.NotNil(t, jsonFormatter)
	assert.True(t, ok)

	jsonExtFormatter, ok := NewFormatter("json-logrus").(*logrus.JSONFormatter)
	assert.NotNil(t, jsonExtFormatter)
	assert.True(t, ok)

	unknownFormatter, ok := NewFormatter("unknown").(*logrus.TextFormatter)
	assert.NotNil(t, unknownFormatter)
	assert.True(t, ok)
}

type testFormatter struct{}

func (*testFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

// Verifies: STK-REQ-088, SYS-REQ-176, SW-REQ-163
// SW-REQ-163:nominal:nominal
// SW-REQ-163:boundary:nominal
// SW-REQ-163:determinism:nominal
func TestLogGlobals(t *testing.T) {
	oldFormatter := log.Formatter
	oldRawFormatter := rawLog.Formatter
	oldLevel := log.Level
	t.Cleanup(func() {
		log.Formatter = oldFormatter
		rawLog.Formatter = oldRawFormatter
		log.Level = oldLevel
	})

	t.Setenv("TYK_LOGFORMAT", "json")
	t.Setenv("TYK_LOGLEVEL", "WARN")

	assert.Equal(t, "warn", getenv("TYK_LOGLEVEL"))
	setupGlobals()

	assert.Same(t, log, Get())
	assert.Same(t, rawLog, GetRaw())
	assert.IsType(t, &JSONFormatter{}, Get().Formatter)
	assert.Equal(t, logrus.WarnLevel, Get().Level)
	assert.IsType(t, &RawFormatter{}, GetRaw().Formatter)

	output, err := GetRaw().Formatter.Format(&logrus.Entry{Message: "raw message"})
	assert.NoError(t, err)
	assert.Equal(t, "raw message", string(output))
}

func BenchmarkFormatter(b *testing.B) {
	b.Run("json", func(b *testing.B) {
		benchmarkFormatter(b, NewFormatter("json"))
	})
	b.Run("json-logrus", func(b *testing.B) {
		benchmarkFormatter(b, NewFormatter("json-logrus"))
	})
	b.Run("default", func(b *testing.B) {
		benchmarkFormatter(b, NewFormatter(""))
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

// Verifies: STK-REQ-088, SYS-REQ-176, SW-REQ-163
// SW-REQ-163:nominal:nominal
// SW-REQ-163:boundary:nominal
// SW-REQ-163:encoding_safety:nominal
// SW-REQ-163:determinism:nominal
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

	t.Run("data key nests fields and timestamp can be disabled", func(t *testing.T) {
		entry := &logrus.Entry{
			Data:    logrus.Fields{"prefix": "test"},
			Time:    time.Date(2026, 6, 21, 7, 0, 0, 0, time.UTC),
			Level:   logrus.InfoLevel,
			Message: "test message",
		}
		nested := &JSONFormatter{DataKey: "fields", DisableTimestamp: true}

		output, err := nested.Format(entry)

		assert.NoError(t, err)
		assert.Contains(t, string(output), `"fields":{"prefix":"test"}`)
		assert.NotContains(t, string(output), `"time"`)
	})
}

// Verifies: STK-REQ-088, SYS-REQ-176, SW-REQ-163
// SW-REQ-163:nominal:nominal
// SW-REQ-163:boundary:nominal
// SW-REQ-163:determinism:nominal
func TestTranslationFormatter(t *testing.T) {
	oldFormatter := log.Formatter
	oldTranslations := translations
	t.Cleanup(func() {
		log.Formatter = oldFormatter
		translations = oldTranslations
	})

	log.Formatter = &testFormatter{}
	LoadTranslations(map[string]interface{}{
		"200": "request ok",
		"nested": map[string]interface{}{
			"created": "created response",
		},
	})

	assert.Equal(t, "request ok", translations["200"])
	assert.Equal(t, "created response", translations["nested.created"])
	assert.IsType(t, &TranslationFormatter{}, log.Formatter)

	output, err := log.Formatter.Format(&logrus.Entry{
		Data:    logrus.Fields{"code": "200"},
		Message: "Finished",
	})
	assert.NoError(t, err)
	assert.Equal(t, "request ok", string(output))

	output, err = log.Formatter.Format(&logrus.Entry{
		Data:    logrus.Fields{"code": "404"},
		Message: "Finished",
	})
	assert.NoError(t, err)
	assert.Equal(t, "Finished", string(output))
}

// Verifies: STK-REQ-088, SYS-REQ-176, SW-REQ-163
// MCDC SYS-REQ-176: log_formatters_operation_terminal=T => TRUE
// MCDC SW-REQ-163: log_formatters_operation_terminal=T => TRUE
// STK-REQ-088:STK-REQ-088-AC-01:acceptance
// SW-REQ-163:nominal:nominal
// SW-REQ-163:boundary:nominal
// SW-REQ-163:encoding_safety:nominal
// SW-REQ-163:determinism:nominal
func TestLogFormattersReqProof(t *testing.T) {
	oldFormatter := log.Formatter
	oldRawFormatter := rawLog.Formatter
	oldLevel := log.Level
	oldTranslations := translations
	t.Cleanup(func() {
		log.Formatter = oldFormatter
		rawLog.Formatter = oldRawFormatter
		log.Level = oldLevel
		translations = oldTranslations
	})

	assert.IsType(t, &logrus.TextFormatter{}, NewFormatter(""))
	assert.IsType(t, &JSONFormatter{}, NewFormatter("json"))
	assert.IsType(t, &logrus.JSONFormatter{}, NewFormatter("json-logrus"))
	assert.IsType(t, &logrus.TextFormatter{}, NewFormatter("unknown"))

	t.Setenv("TYK_LOGFORMAT", "json")
	t.Setenv("TYK_LOGLEVEL", "WARN")
	assert.Equal(t, "warn", getenv("TYK_LOGLEVEL"))
	setupGlobals()
	assert.Same(t, log, Get())
	assert.Same(t, rawLog, GetRaw())
	assert.IsType(t, &JSONFormatter{}, Get().Formatter)
	assert.Equal(t, logrus.WarnLevel, Get().Level)
	assert.IsType(t, &RawFormatter{}, GetRaw().Formatter)

	rawOutput, err := GetRaw().Formatter.Format(&logrus.Entry{Message: "raw message"})
	assert.NoError(t, err)
	assert.Equal(t, "raw message", string(rawOutput))

	formatter := &JSONFormatter{TimestampFormat: time.RFC3339}
	jsonOutput, err := formatter.Format(&logrus.Entry{
		Data: logrus.Fields{
			logrus.ErrorKey: errors.New("test error"),
		},
		Time:    time.Date(2026, 6, 21, 7, 0, 0, 0, time.UTC),
		Level:   logrus.InfoLevel,
		Message: "test message",
	})
	assert.NoError(t, err)
	assert.Contains(t, string(jsonOutput), `"error":"test error"`)
	assert.Contains(t, string(jsonOutput), `"logrus_error":"test error"`)

	nestedOutput, err := (&JSONFormatter{DataKey: "fields", DisableTimestamp: true}).Format(&logrus.Entry{
		Data:    logrus.Fields{"prefix": "test"},
		Time:    time.Date(2026, 6, 21, 7, 0, 0, 0, time.UTC),
		Level:   logrus.InfoLevel,
		Message: "test message",
	})
	assert.NoError(t, err)
	assert.Contains(t, string(nestedOutput), `"fields":{"prefix":"test"}`)
	assert.NotContains(t, string(nestedOutput), `"time"`)

	log.Formatter = &testFormatter{}
	LoadTranslations(map[string]interface{}{
		"200": "request ok",
		"nested": map[string]interface{}{
			"created": "created response",
		},
	})
	assert.Equal(t, "request ok", translations["200"])
	assert.Equal(t, "created response", translations["nested.created"])
	assert.IsType(t, &TranslationFormatter{}, log.Formatter)

	translated, err := log.Formatter.Format(&logrus.Entry{
		Data:    logrus.Fields{"code": "200"},
		Message: "Finished",
	})
	assert.NoError(t, err)
	assert.Equal(t, "request ok", string(translated))

	passthrough, err := log.Formatter.Format(&logrus.Entry{
		Data:    logrus.Fields{"code": "404"},
		Message: "Finished",
	})
	assert.NoError(t, err)
	assert.Equal(t, "Finished", string(passthrough))
}

// Reproduces: KI-LOG-TRANSLATION-NONSTRING-CODE-PANIC
// Verifies: SYS-REQ-176
func TestKnownIssue_TranslationFormatterPanicsOnNonStringCode(t *testing.T) {
	oldTranslations := translations
	t.Cleanup(func() {
		translations = oldTranslations
	})
	translations = map[string]string{"200": "request ok"}

	formatter := &TranslationFormatter{Formatter: &testFormatter{}}
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected panic for non-string code field")
		}
	}()

	_, _ = formatter.Format(&logrus.Entry{
		Data:    logrus.Fields{"code": 200},
		Message: "Finished",
	})
}
