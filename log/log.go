package log

import (
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Wrap global vars with `global.` prefix - avoids common package
// and variable name conflicts.
var global = struct {
	Logger       *logrus.Logger
	RawLog       *logrus.Logger
	Translations map[string]string
}{
	Logger:       logrus.New(),
	RawLog:       logrus.New(),
	Translations: make(map[string]string),
}

// Manage concurrent read/write access to globals.
var globalMu sync.RWMutex

// LoadTranslations takes a map[string]interface and flattens it to map[string]string
// Because translations have been loaded - we internally override log the formatter
// Nested entries are accessible using dot notation.
// example:   `{"foo": {"bar": "baz"}}`
// flattened: `foo.bar: baz`
func LoadTranslations(thing map[string]interface{}) {
	globalMu.Lock()
	defer globalMu.Unlock()

	global.Logger.Formatter = &TranslationFormatter{newLogrusTextFormatter()}
	global.Translations, _ = Flatten(thing)
}

type TranslationFormatter struct {
	*logrus.TextFormatter
}

func (t *TranslationFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	code, ok := entry.Data["code"].(string)
	if !ok {
		return t.TextFormatter.Format(entry)
	}

	globalMu.RLock()
	if v, ok := global.Translations[code]; ok {
		entry.Message = v
	}
	globalMu.RUnlock()

	return t.TextFormatter.Format(entry)
}

type RawFormatter struct{}

func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

func init() {
	global.RawLog.Formatter = new(RawFormatter)
	global.Logger.Formatter = newLogrusTextFormatter()
	global.Logger.Level = getLevel()

}

func getLevel() Level {
	switch strings.ToLower(os.Getenv("TYK_LOGLEVEL")) {
	case "error":
		return logrus.ErrorLevel
	case "warn":
		return logrus.WarnLevel
	case "debug":
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel
	}
}

func Get() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()

	return fromLogrusLogger(global.Logger)
}

func GetRaw() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()

	return fromLogrusLogger(global.RawLog)
}

func New() Logger {
	return fromLogrusLogger(logrus.New())
}

func NewEntry() Logger {
	return New()
}

func WithField(key string, value interface{}) Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()

	return fromLogrusLogger(global.Logger).WithField(key, value)
}

func WithFields(f Fields) Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()

	return fromLogrusLogger(global.Logger).WithFields(f)
}

func WithError(err error) Logger {
	return fromLogrusLogger(global.Logger).WithError(err)
}

func WithPrefix(prefix string) Logger {
	return fromLogrusLogger(global.Logger).WithField("prefix", prefix)
}

func Error(message string) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	fromLogrusLogger(global.Logger).Error(message)
}

func Fatal(message string) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	fromLogrusLogger(global.Logger).Fatal(message)
}

func Warning(message string) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	fromLogrusLogger(global.Logger).Warning(message)
}

var Warn = Warning

func Info(message string) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	fromLogrusLogger(global.Logger).Info(message)
}

func Debug(message string) {
	globalMu.RLock()
	defer globalMu.RUnlock()

	fromLogrusLogger(global.Logger).Error(message)
}
