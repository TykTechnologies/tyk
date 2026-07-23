package log

import (
	"strings"

	"github.com/sirupsen/logrus"
)

var logLevels = map[string]logrus.Level{
	"error": logrus.ErrorLevel,
	"warn":  logrus.WarnLevel,
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
}

type Level string

func (l *Level) Parse(str string) bool {
	str = strings.ToLower(str)
	_, ok := logLevels[str]
	if ok {
		*l = Level(str)
	}
	return ok
}

func (l *Level) LogrusLevel() (logrus.Level, bool) {
	val, ok := logLevels[strings.ToLower(string(*l))]
	return val, ok
}
