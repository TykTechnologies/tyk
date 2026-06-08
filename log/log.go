package log

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
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

func IsLegacyFormatter(formatter logrus.Formatter) bool {
	textFormatter, ok := formatter.(*logrus.TextFormatter)

	return ok && textFormatter.TimestampFormat == LegacyTimestampFormat
}

// InjectTestHook
// Inject hook for testing.
func InjectTestHook(t *testing.T) *TestHook {
	t.Helper()

	hook := &TestHook{new(logrustest.Hook)}
	log.AddHook(hook)

	t.Cleanup(func() {
		clone := make(logrus.LevelHooks, len(log.Hooks))

		for level, hooks := range log.Hooks {
			clone[level] = lo.Filter(hooks, func(item logrus.Hook, _ int) bool {
				return item == hook
			})
		}

		log.ReplaceHooks(clone)
	})

	return hook
}

type localTestHook = logrustest.Hook

type TestHook struct {
	*localTestHook
}

func NewTestHookWithHook(base *logrustest.Hook) *TestHook {
	return &TestHook{base}
}

func (h *TestHook) SomeBy(predicate func(*logrus.Entry) bool) bool {
	return lo.SomeBy(h.AllEntries(), predicate)
}

func (h *TestHook) FilterBy(predicate func(*logrus.Entry) bool) []*logrus.Entry {
	return lo.Filter(h.AllEntries(), func(item *logrus.Entry, _ int) bool {
		return predicate(item)
	})
}

func (h *TestHook) CountBy(predicate func(*logrus.Entry) bool) int {
	return lo.CountBy(h.AllEntries(), predicate)
}
