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

func getenv(names ...string) string {
	for _, name := range names {
		val := os.Getenv(name)
		if val == "" {
			continue
		}
		return strings.ToLower(val)
	}
	return ""
}

var logLevels = map[string]logrus.Level{
	"error": logrus.ErrorLevel,
	"warn":  logrus.WarnLevel,
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
}

func setupGlobals() {
	format := getenv("TYK_LOGFORMAT", "TYK_GW_LOGFORMAT")
	logLevel := getenv("TYK_LOGLEVEL", "TYK_GW_LOGLEVEL")

	log.Formatter = NewFormatter(format)

	if level, ok := logLevels[logLevel]; ok {
		log.Level = level
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
