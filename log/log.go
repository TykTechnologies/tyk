package log

import (
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
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

func Get() *logrus.Logger {
	switch strings.ToLower(os.Getenv("TYK_LOGLEVEL")) {
	case "error":
		log.Level = logrus.ErrorLevel
	case "warn":
		log.Level = logrus.WarnLevel
	case "debug":
		log.Level = logrus.DebugLevel
	default:
		log.Level = logrus.InfoLevel
	}
	return log
}

func GetRaw() *logrus.Logger {
	return rawLog
}
