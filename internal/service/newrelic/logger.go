package newrelic

import (
	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Entry
}

var _ newrelic.Logger = &Logger{}

// SW-REQ-067
func NewLogger(e *logrus.Entry) *Logger {
	return &Logger{e}
}

// SW-REQ-067
func (l *Logger) Error(msg string, c map[string]interface{}) {
	l.WithFields(c).Error(msg)
}

// SW-REQ-067
func (l *Logger) Warn(msg string, c map[string]interface{}) {
	l.WithFields(c).Warn(msg)
}

// SW-REQ-067
func (l *Logger) Info(msg string, c map[string]interface{}) {
	l.WithFields(c).Info(msg)
}

// SW-REQ-067
func (l *Logger) Debug(msg string, c map[string]interface{}) {
	l.WithFields(c).Debug(msg)
}

// SW-REQ-067
func (l *Logger) DebugEnabled() bool {
	return l.Level >= logrus.DebugLevel
}
