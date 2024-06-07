package log

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/maps"
)

var (
	log            = logrus.New()
	rawLog         = logrus.New()
	transactionLog = logrus.New()
	translations   = make(map[string]string)
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

// TransactionFormatter formats logs for transactions in the desired format
type TransactionFormatter struct {
	*logrus.JSONFormatter
}

func (f *TransactionFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	message, err := f.JSONFormatter.Format(entry)
	if err != nil {
		log.Error("Could not format transaction log entry: %v", err)
	}
	return message, nil
}

//nolint:gochecknoinits
func init() {
	formatter := new(logrus.TextFormatter)
	formatter.TimestampFormat = `Jan 02 15:04:05`
	formatter.FullTimestamp = true
	formatter.DisableColors = true

	log.Formatter = formatter

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

	// Initialize and configure the transactionLogger and JSONFormatter
	jsonFormatter := new(logrus.JSONFormatter)
	transactionLog.Formatter = &TransactionFormatter{JSONFormatter: jsonFormatter}
	transactionLog.Level = logrus.InfoLevel
}

func Get() *logrus.Logger {
	return log
}

func GetRaw() *logrus.Logger {
	return rawLog
}

func GetTransactionLogger() *logrus.Logger {
	return transactionLog
}
