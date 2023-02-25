package log

import (
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
)

func NewAbstractLogger() *abstractlogger.LogrusLogger {
	level := getLevel()
	return abstractlogger.NewLogrusLogger(logrus.New(), absLoggerLevel(level))
}

func absLoggerLevel(level Level) abstractlogger.Level {
	switch level {
	case logrus.ErrorLevel:
		return abstractlogger.ErrorLevel
	case logrus.WarnLevel:
		return abstractlogger.WarnLevel
	case logrus.DebugLevel:
		return abstractlogger.DebugLevel
	}
	return abstractlogger.InfoLevel
}
