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

type Format string

const (
	FormatText   Format = "text"
	FormatJson   Format = "json"
	FormatLegacy Format = "legacy"
)

const (
	LegacyTimestampFormat = "Jan 02 15:04:05"
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
	format := Format(getenv("TYK_LOGFORMAT", "TYK_GW_LOGFORMAT"))
	SetupFormatter(format)

	logLevel := getenv("TYK_LOGLEVEL", "TYK_GW_LOGLEVEL")

	if level, ok := logLevels[logLevel]; ok {
		log.Level = level
	}

	rawLog.Formatter = new(RawFormatter)
}

func SetupFormatter(format Format) {
	log.Formatter = NewFormatter(format)

	// non legacy formatter does not set up global logrus formatter
	if format != FormatLegacy {
		logrus.StandardLogger().Formatter = log.Formatter
	}
}

// Get returns the default configured logger.
func Get() *logrus.Logger {
	return log
}

// GetRaw is used internally. Should likely be removed first, do not rely on it.
func GetRaw() *logrus.Logger {
	return rawLog
}

func NewFormatter(format Format) logrus.Formatter {
	switch format {
	case FormatLegacy:
		return newFormatterLegacy()
	case FormatJson:
		return newFormatterJson()
	case FormatText:
		return newFormatterText()
	default:
		return newFormatterText()
	}
}

func newFormatterText() logrus.Formatter {
	return &logrus.TextFormatter{
		TimestampFormat: time.RFC3339,
		FullTimestamp:   true,
		DisableColors:   true,
	}
}

func newFormatterJson() logrus.Formatter {
	return &JSONFormatter{
		TimestampFormat: time.RFC3339,
	}
}

func newFormatterLogrusJson() logrus.Formatter {
	return &logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	}
}

func newFormatterLegacy() logrus.Formatter {
	return &logrus.TextFormatter{
		TimestampFormat: LegacyTimestampFormat,
		FullTimestamp:   true,
		DisableColors:   true,
	}
}
