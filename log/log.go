package log

import (
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	log          = logrus.New()
	rawLog       = logrus.New()
	translations = make(map[string]string)
)

// RawFormatter returns the logrus entry message as bytes.
type RawFormatter struct{}

// Format returns the entry.Message as a []byte.
func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

//nolint:gochecknoinits
func init() {
	setupGlobals()
}

func setupGlobals() {
	log.Formatter = NewFormatter(os.Getenv("TYK_LOGFORMAT"))

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

	rawLog.Formatter = new(RawFormatter)
}

// Get returns the default configured logger.
func Get() *logrus.Logger {
	return log
}

// GetRaw is used internally. Should likely be removed first, do not rely on it.
func GetRaw() *logrus.Logger {
	return rawLog
}

// formatterIndex serves as a list of formatters supported.
// it can be extended from test scope for benchmark purposes.
var (
	formatterIndex = map[string]func() logrus.Formatter{
		"default": func() logrus.Formatter {
			return &logrus.TextFormatter{
				TimestampFormat: "Jan 02 15:04:05",
				FullTimestamp:   true,
				DisableColors:   true,
			}
		},
		"json": func() logrus.Formatter {
			return &JSONFormatter{
				TimestampFormat: time.RFC3339,
			}
		},
	}
)

func NewFormatter(format string) logrus.Formatter {
	ctor, ok := formatterIndex[format]
	if !ok {
		ctor, _ = formatterIndex["default"]
	}
	return ctor()
}
