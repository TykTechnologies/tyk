package errpack_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

func Test_Errpack(t *testing.T) {
	logLevels := func() []logrus.Level {
		return []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
			logrus.InfoLevel,
			logrus.DebugLevel,
			logrus.TraceLevel,
		}
	}

	t.Run("#Wrap", func(t *testing.T) {
		t.Run("returns nil if nil is given", func(t *testing.T) {
			res := errpack.Wrap(nil, errpack.WithLogLevel(logrus.ErrorLevel))
			assert.Nil(t, res)
		})
	})

	t.Run("#LogLevel", func(t *testing.T) {
		t.Run("returns fallback if error is nil or now wrapped", func(t *testing.T) {
			rawErr := errors.New("raw")

			for _, level := range logLevels() {
				computed := errpack.LogLevel(nil, level)
				assert.Equal(t, level, computed)

				computed = errpack.LogLevel(rawErr, level)
				assert.Equal(t, level, computed)
			}
		})

		t.Run("returns level of wrapped and returns the same message", func(t *testing.T) {
			rawErr := errors.New("raw")

			for _, level := range logLevels() {
				wrapped := errpack.Wrap(rawErr, errpack.WithLogLevel(level))
				computed := errpack.LogLevel(wrapped, level)

				assert.Equal(t, level, computed)
				assert.Equal(t, "raw", wrapped.Error())
				assert.True(t, errors.Is(wrapped, rawErr), "finds error in chain")
			}
		})

		t.Run("returns level highest level of wrapped error", func(t *testing.T) {
			rawErr := errors.New("src")
			wrapped1 := errpack.Wrap(rawErr, errpack.WithLogLevel(logrus.DebugLevel))
			wrapped2 := errpack.Wrap(wrapped1, errpack.WithLogLevel(logrus.WarnLevel))

			assert.Equal(t, logrus.WarnLevel, errpack.LogLevel(wrapped2, logrus.TraceLevel))
			assert.Equal(t, logrus.DebugLevel, errpack.LogLevel(wrapped1, logrus.TraceLevel))

			assert.ErrorIs(t, wrapped2, rawErr)
			assert.ErrorIs(t, wrapped2, wrapped1)
			assert.ErrorIs(t, wrapped1, rawErr)
			assert.NotErrorIs(t, wrapped1, wrapped2)
		})
	})
}
