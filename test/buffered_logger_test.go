package test

import (
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewBufferingLogger(t *testing.T) {
	type checkFn func(*BufferedLogger)

	var (
		check = func(fns ...checkFn) []checkFn { return fns }

		isNil = func(bl *BufferedLogger) {
			assert.NotNil(t, bl, "Expected NewBufferingLogger to return a non-nil *BufferedLogger")
		}

		isSingleton = func(bl1 *BufferedLogger) {
			bl2 := NewBufferingLogger()
			assert.Equal(t, bl1, bl2, "Expected NewBufferingLogger to exhibit singleton behavior")
		}

		isBufferingFormatter = func(bl *BufferedLogger) {
			_, ok := bl.Formatter.(*BufferingFormatter)
			assert.True(t, ok, "Expected logger.Formatter to be of type *BufferingFormatter")
		}

		isEmpty = func(bl *BufferedLogger) {
			assert.NotNil(t, bl.bufferingFormatter.buffer, "Expected buffer to be initialized")
			assert.Len(t, bl.bufferingFormatter.buffer, 0, "Expected buffer to be empty")
		}
	)

	tests := []struct {
		name   string
		before func(*BufferedLogger)
		checks []checkFn
	}{
		{
			name:   "NewBufferingLogger initialize",
			before: func(*BufferedLogger) {},
			checks: check(isNil, isSingleton, isBufferingFormatter, isEmpty),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(*testing.T) {
			bl := NewBufferingLogger()

			if tt.before != nil {
				tt.before(bl)
			}

			for _, check := range tt.checks {
				check(bl)
			}
		})
	}
}

func TestBufferingFormatterFormat(t *testing.T) {
	type checkFn func(*BufferingFormatter, error)

	var (
		check = func(fns ...checkFn) []checkFn { return fns }

		hasError = func(_ *BufferingFormatter, err error) {
			assert.Nil(t, err, "Expected no error from Format method")
		}

		logLen = func(count int) checkFn {
			return func(f *BufferingFormatter, _ error) {
				assert.Len(t, f.buffer, count, "Expected buffer to have %d log", count)
			}
		}

		content = func(expected *BufferedLog) checkFn {
			return func(f *BufferingFormatter, _ error) {
				log := f.buffer[0]
				assert.Equal(t, expected.Message, log.Message, "Expected log message to match")
				assert.Equal(t, expected.Time.UTC(), log.Time, "Expected log time to be in UTC")
				assert.Equal(t, expected.Level, log.Level, "Expected log level to match")
			}
		}

		_now = time.Now()
	)

	tests := []struct {
		name   string
		entry  *logrus.Entry
		before func(*BufferingFormatter)
		checks []checkFn
	}{
		{
			name: "initialize",
			entry: &logrus.Entry{
				Message: "test message",
				Time:    _now,
				Level:   logrus.InfoLevel,
			},
			checks: check(
				hasError,
				logLen(1),
				content(&BufferedLog{
					Message: "test message",
					Time:    _now,
					Level:   logrus.InfoLevel,
				}),
			),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(*testing.T) {
			f := &BufferingFormatter{
				bufferMutex: sync.Mutex{},
				buffer:      []*BufferedLog{},
			}

			if tt.before != nil {
				tt.before(f)
			}

			_, err := f.Format(tt.entry)

			for _, check := range tt.checks {
				check(f, err)
			}
		})
	}
}

func TestBufferedLoggerGetLogs(t *testing.T) {
	type checkFn func(*testing.T, *BufferedLogger)

	var (
		check = func(fns ...checkFn) []checkFn { return fns }

		entries = []*BufferedLog{
			{Message: "info log", Time: time.Now(), Level: logrus.InfoLevel},
			{Message: "debug log", Time: time.Now(), Level: logrus.DebugLevel},
			{Message: "error log", Time: time.Now(), Level: logrus.ErrorLevel},
		}

		hasLogs = func(level logrus.Level, count int) checkFn {
			return func(t *testing.T, f *BufferedLogger) {
				t.Helper()
				logs := f.GetLogs(level)
				assert.Len(t, logs, count, "Expected buffer to have %d log", count)
			}
		}
	)

	tests := []struct {
		name   string
		before func(*BufferedLogger)
		checks []checkFn
	}{
		{
			name:   "info-logs",
			before: func(bl *BufferedLogger) { bl.bufferingFormatter.buffer = entries },
			checks: check(hasLogs(logrus.InfoLevel, 1)),
		},
		{
			name:   "debug-logs",
			before: func(bl *BufferedLogger) { bl.bufferingFormatter.buffer = entries },
			checks: check(hasLogs(logrus.DebugLevel, 1)),
		},
		{
			name:   "error-logs",
			before: func(bl *BufferedLogger) { bl.bufferingFormatter.buffer = entries },
			checks: check(hasLogs(logrus.ErrorLevel, 1)),
		},
		{
			name:   "no-entries-logs",
			before: func(bl *BufferedLogger) { bl.bufferingFormatter.buffer = entries },
			checks: check(hasLogs(logrus.WarnLevel, 0)),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bl := NewBufferingLogger()

			if tt.before != nil {
				tt.before(bl)
			}

			for _, check := range tt.checks {
				check(t, bl)
			}
		})
	}
}

func TestBufferedLoggerClearLogs(t *testing.T) {
	type checkFn func(*testing.T, *BufferedLogger)

	var (
		check = func(fns ...checkFn) []checkFn { return fns }

		buffer = []*BufferedLog{
			{Message: "log 1", Time: time.Now(), Level: logrus.InfoLevel},
			{Message: "log 2", Time: time.Now(), Level: logrus.WarnLevel},
		}

		empty = func(empty bool) checkFn {
			return func(t *testing.T, bl *BufferedLogger) {
				t.Helper()
				if empty {
					assert.LessOrEqual(t, 0, len(bl.bufferingFormatter.buffer), 0, "Expected buffer to be empty")
				} else {
					assert.Greater(t, len(bl.bufferingFormatter.buffer), 0, "Expected buffer to not be empty")
				}
			}
		}
	)

	tests := []struct {
		name   string
		before func(*BufferedLogger)
		checks []checkFn
	}{
		{
			name: "empty-before-clear",
			before: func(bl *BufferedLogger) {
				bl.bufferingFormatter.buffer = []*BufferedLog{}
			},
			checks: check(empty(true)),
		},
		{
			name: "non-empty-before-clear",
			before: func(bl *BufferedLogger) {
				bl.bufferingFormatter.buffer = buffer
			},
			checks: check(empty(true)),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bl := NewBufferingLogger()

			if tt.before != nil {
				tt.before(bl)
			}

			bl.ClearLogs()
			for _, check := range tt.checks {
				check(t, bl)
			}
		})
	}
}
