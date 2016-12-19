package logger

import (
	"os"
	"strings"

	"github.com/TykTechnologies/logrus"
	prefixed "github.com/TykTechnologies/logrus-prefixed-formatter"
)

var log = logrus.New()

func init() {
	log.Formatter = new(prefixed.TextFormatter)
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
