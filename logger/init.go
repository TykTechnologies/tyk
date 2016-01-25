package logger

import (
	"github.com/Sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"os"
	"strings"
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
	default:
		log.Level = logrus.InfoLevel
	}

	return log
}
