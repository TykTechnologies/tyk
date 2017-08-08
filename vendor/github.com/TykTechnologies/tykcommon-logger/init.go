package logger

import (
	"os"
	"strings"

	"github.com/TykTechnologies/logrus"
	prefixed "github.com/TykTechnologies/logrus-prefixed-formatter"
)

var log = logrus.New()
var rawLog = logrus.New()

type RawFormatter struct{}

func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
    return []byte(entry.Message), nil
}

func init() {
	log.Formatter = new(prefixed.TextFormatter)
    rawLog.Formatter = new(RawFormatter)
}

func GetLogger() *logrus.Logger {
	level := os.Getenv("TYK_LOGLEVEL")
	if level == "" {
		level = "info"
	}

	switch strings.ToLower(level) {
	case "warn":
		log.Level = logrus.WarnLevel
	case "info":
		log.Level = logrus.InfoLevel
	case "debug":
		log.Level = logrus.DebugLevel
	case "error":
		log.Level = logrus.ErrorLevel
	default:
		log.Level = logrus.InfoLevel
	}

	return log
}

func GetRaw() *logrus.Logger {
	return rawLog
}
