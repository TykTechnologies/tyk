package newrelic

import (
	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Entry
}

var _ newrelic.Logger = &Logger{}

func NewLogger(e *logrus.Entry) *Logger {
	return &Logger{e}
}

func (l *Logger) Error(msg string, c map[string]interface{}) {
	l.WithFields(c).Error(msg)
}
func (l *Logger) Warn(msg string, c map[string]interface{}) {
	l.WithFields(c).Warn(msg)
}
func (l *Logger) Info(msg string, c map[string]interface{}) {
	l.WithFields(c).Info(msg)
}
func (l *Logger) Debug(msg string, c map[string]interface{}) {
	l.WithFields(c).Debug(msg)
}
func (l *Logger) DebugEnabled() bool {
	return l.Level >= logrus.DebugLevel
}
