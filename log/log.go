package log

import (
	"fmt"
	"os"
	"strings"
	"time"

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
type TransactionFormatter struct{}

func (f *TransactionFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := time.Now().Format(time.RFC3339)
	userAgent, _ := entry.Data["userAgent"].(string)
	requestMethod, _ := entry.Data["requestMethod"].(string)
	requestUri, _ := entry.Data["requestUri"].(string)
	protocol, _ := entry.Data["protocol"].(string)
	responseCode, _ := entry.Data["responseCode"].(int)
	upstreamAddress, _ := entry.Data["upstreamAddress"].(string)
	clientIp, _ := entry.Data["clientIp"].(string)
	message := fmt.Sprintf("%s \"%s %s %s\" %d \"%s\" \"%s\" %s\n", timestamp, requestMethod, requestUri, protocol, responseCode, userAgent, upstreamAddress, clientIp)
	return []byte(message), nil
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
	transactionLog.Formatter = new(TransactionFormatter)

	// Set log level for transactionLog as needed
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
