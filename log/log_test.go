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
}

type testFormatter struct{}

func (*testFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
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
