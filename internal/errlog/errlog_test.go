package errlog_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/errlog"
)

func Test_ErrLog(t *testing.T) {
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
			res := errlog.Wrap(nil, logrus.ErrorLevel)
			assert.Nil(t, res)
		})
	})

	t.Run("#Level", func(t *testing.T) {
		t.Run("returns fallback if error is nil or now wrapped", func(t *testing.T) {
			rawErr := errors.New("raw")

			for _, level := range logLevels() {
				computed := errlog.Level(nil, level)
				assert.Equal(t, level, computed)

				computed = errlog.Level(rawErr, level)
				assert.Equal(t, level, computed)
			}
		})

		t.Run("returns level of wrapped and returns the same message", func(t *testing.T) {
			rawErr := errors.New("raw")

			for _, level := range logLevels() {
				wrapped := errlog.Wrap(rawErr, level)
				computed := errlog.Level(wrapped, level)

				assert.Equal(t, level, computed)
				assert.Equal(t, "raw", wrapped.Error())
				assert.True(t, errors.Is(wrapped, rawErr), "finds error in chain")
			}
		})

		t.Run("returns level highest level of wrapped error", func(t *testing.T) {
			rawErr := errors.New("src")
			wrapped1 := errlog.Wrap(rawErr, logrus.DebugLevel)
			wrapped2 := errlog.Wrap(wrapped1, logrus.WarnLevel)

			assert.Equal(t, logrus.WarnLevel, errlog.Level(wrapped2, logrus.TraceLevel))
			assert.Equal(t, logrus.DebugLevel, errlog.Level(wrapped1, logrus.TraceLevel))

			assert.ErrorIs(t, wrapped2, rawErr)
			assert.ErrorIs(t, wrapped2, wrapped1)
			assert.ErrorIs(t, wrapped1, rawErr)
			assert.NotErrorIs(t, wrapped1, wrapped2)
		})
	})
}
