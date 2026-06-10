package log

import (
	stdlog "log"
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

// logrusWriter is a custom io.Writer that redirects standard library log output
// directly to Tyk's logrus logger.
type logrusWriter struct {
	logger *logrus.Logger
}

func (w *logrusWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Standard log package appends a trailing newline, which we trim
	// to avoid double newlines or empty lines in structured log outputs.
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	w.logger.Print(msg)
	return len(p), nil
}

func SetupFormatter(format Format) {
	log.Formatter = NewFormatter(format)

	// non legacy formatter does not set up global logrus formatter
	if format != FormatLegacy {
		logrus.StandardLogger().Formatter = log.Formatter
	}

	// Redirect standard log output to Tyk's logrus logger
	stdlog.SetOutput(&logrusWriter{logger: log})
	// Disable standard log flags (date, time, etc.) to prevent double-timestamping
	stdlog.SetFlags(0)
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

func IsLegacyFormatter(formatter logrus.Formatter) bool {
	textFormatter, ok := formatter.(*logrus.TextFormatter)

	return ok && textFormatter.TimestampFormat == LegacyTimestampFormat
}
