package log

import (
	"encoding/json"
	"fmt"
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
	formatterRegistry = map[Format]func() logrus.Formatter{
		FormatText:   newFormatterText,
		FormatJson:   newFormatterJson,
		FormatLegacy: newFormatterLegacy,
	}
)

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
	formatterFactory, ok := formatterRegistry[format]
	if !ok {
		return nil, fmt.Errorf("unknown formatter %q", format)
	}

	formatter := formatterFactory()

	if err := applySnakeCaseOptions(opts, formatter); err != nil {
		return nil, fmt.Errorf("failed to apply options to %s formatter: %w", format, err)
	}

	return formatter, nil
}

// applySnakeCaseOptions strips underscores from JSON keys so that snake_case
// transparently maps to CamelCase struct fields via Go's case-insensitive unmarshaler.
func applySnakeCaseOptions(data json.RawMessage, target interface{}) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	normalizedMap := make(map[string]json.RawMessage, len(rawMap))
	for key, val := range rawMap {
		normalizedKey := strings.ReplaceAll(key, "_", "")
		normalizedMap[normalizedKey] = val
	}

	transformedData, err := json.Marshal(normalizedMap)
	if err != nil {
		return err
	}

	return json.Unmarshal(transformedData, target)
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
