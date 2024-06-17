package log

import (
	"errors"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewFormatter(t *testing.T) {
	textFormatter, ok := NewFormatter("").(*logrus.TextFormatter)
	assert.NotNil(t, textFormatter)
	assert.True(t, ok)

	jsonFormatter, ok := NewFormatter("json").(*logrus.JSONFormatter)
	assert.NotNil(t, jsonFormatter)
	assert.True(t, ok)
}

func BenchmarkFormatter(b *testing.B) {
	b.Run("json", func(b *testing.B) {
		benchmarkFormatter(b, "json")
	})
	b.Run("default", func(b *testing.B) {
		benchmarkFormatter(b, "")
	})
}

func benchmarkFormatter(b *testing.B, formatter string) {
	logger := logrus.New()
	logger.Out = io.Discard
	logger.Formatter = NewFormatter(formatter)

	err := errors.New("Test error value")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i <= b.N; i++ {
		logger.WithError(err).WithField("prefix", "test").Info("This is a typical log message")
	}
}
