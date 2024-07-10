package log

import (
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/maps"
)

var (
	log          = logrus.New()
	rawLog       = logrus.New()
	translations = make(map[string]string)
)

// LoadTranslations takes a map[string]interface and flattens it to map[string]string
// Because translations have been loaded - we internally override log the formatter
// Nested entries are accessible using dot notation.
// example:   `{"foo": {"bar": "baz"}}`
// flattened: `foo.bar: baz`
func LoadTranslations(thing map[string]interface{}) {
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = `Jan 02 15:04:05`
	formatter.FullTimestamp = true
	formatter.DisableColors = true
	log.Formatter = &TranslationFormatter{formatter}
	translations, _ = maps.Flatten(thing)
}

type TranslationFormatter struct {
	*logrus.TextFormatter
}

func (t *TranslationFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if code, ok := entry.Data["code"]; ok {
		if translation, ok := translations[code.(string)]; ok {
			entry.Message = translation
		}
	}
	return t.TextFormatter.Format(entry)
}

type RawFormatter struct{}

func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

//nolint:gochecknoinits
func init() {
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

func Get() *logrus.Logger {
	return log
}

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
