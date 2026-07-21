package log

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	EnvTykLogformat   = "TYK_LOGFORMAT"
	EnvTykGwLogformat = "TYK_GW_LOGFORMAT"
	EnvTykLoglevel    = "TYK_LOGLEVEL"
	EnvTykGwLoglevel  = "TYK_GW_LOGLEVEL"
)

const (
	LegacyTimestampFormat = "Jan 02 15:04:05"
)

var (
	log               = New()
	rawLog            = newRawLog()
	translations      = make(map[string]string)
	formatterRegistry = map[Format]formatterFactory{
		FormatText: func(_ json.RawMessage) (logrus.Formatter, error) {
			return newFormatterText(), nil
		},
		FormatJson: func(_ json.RawMessage) (logrus.Formatter, error) {
			return newFormatterJson(), nil
		},
		FormatLegacy: func(_ json.RawMessage) (logrus.Formatter, error) {
			return newFormatterLegacy(), nil
		},
	}
)

type formatterFactory func(options json.RawMessage) (logrus.Formatter, error)

func newRawLog() *logrus.Logger {
	var l = logrus.New()
	l.SetFormatter(&RawFormatter{})
	return l
}

// RawFormatter returns the logrus entry message as bytes.
type RawFormatter struct{}

// Format returns the entry.Message as a []byte.
func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

// Get returns the default configured logger.
func Get() *Logger {
	return log
}

// GetRaw is used internally. Should likely be removed first, do not rely on it.
func GetRaw() *logrus.Logger {
	return rawLog
}

// NewFormatter builds formatter
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

func MakeFormatter(format Format, opts json.RawMessage) (logrus.Formatter, error) {
	if formatter, ok := formatterRegistry[format]; ok {
		return formatter(opts)
	}

	return nil, fmt.Errorf("unknown formatter %q", format)
}

func newFormatterText() logrus.Formatter {
	return &logrus.TextFormatter{
		FieldMap:        defaultFieldMap(),
		TimestampFormat: time.RFC3339,
		FullTimestamp:   true,
		DisableColors:   true,
	}
}

func newFormatterJson() logrus.Formatter {
	return &JSONFormatter{
		FieldMap:        NewFieldMap(defaultFieldMap()),
		TimestampFormat: time.RFC3339,
	}
}

func newFormatterLogrusJson() logrus.Formatter {
	return &logrus.JSONFormatter{
		FieldMap:        defaultFieldMap(),
		TimestampFormat: time.RFC3339,
	}
}

func newFormatterLegacy() logrus.Formatter {
	return &logrus.TextFormatter{
		FieldMap:        logrus.FieldMap{},
		TimestampFormat: LegacyTimestampFormat,
		FullTimestamp:   true,
		DisableColors:   true,
	}
}

func CoalesceEnvOr[T any, P interface {
	*T
	Parse(string) bool
}](fallback T, envNames ...string) T {

	for _, envName := range envNames {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}

		var value T
		if P(&value).Parse(raw) {
			return value
		}
	}

	return fallback
}

func CoalesceValidEnv[T any, P interface {
	*T
	Parse(string) bool
	Valid() bool
}](envNames ...string) (T, bool) {

	for _, envName := range envNames {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}

		var value T
		if P(&value).Parse(raw) {
			return value, true
		}
	}

	var zero T
	return zero, false
}

type Format string

const (
	FormatText   Format = "text"
	FormatJson   Format = "json"
	FormatLegacy Format = "legacy"
)

func (f *Format) Parse(str string) bool {
	s := Format(strings.ToLower(str))

	if s.Valid() {
		*f = s
		return true
	}

	return false
}

func (f *Format) Valid() bool {
	switch *f {
	case FormatText, FormatJson, FormatLegacy:
		return true
	}
	return false
}

func defaultFieldMap() logrus.FieldMap {
	return logrus.FieldMap{
		logrus.FieldKeyMsg: "message",
	}
}
