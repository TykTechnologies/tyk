package log

import (
	"io"
	"os"
	"strings"
	"sync"
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
	tmpLoggerHook          = &tmpLogsCollector{}
	emergencyLogger        = newEmergencyLogger()
	tmpLogger              = newTmpLogger(tmpLoggerHook, emergencyLogger)
	log                    = &loggerWrapper{tmpLogger}
	rawLog                 = newRawLog()
	translations           = make(map[string]string)
	once                   = invokeOnce{}
	_               Logger = new(loggerWrapper)
)

type (
	RawLogger interface {
		logrus.Ext1FieldLogger
	}

	// LegacyLogger
	// The logger with deprecated legacy methods.
	LegacyLogger interface {

		// NewEntry
		// Deprecated. Stop using direct logrus structures.
		NewEntry() *logrus.Entry

		// AsLogrus
		// Deprecated. Stop using direct logrus structures.
		AsLogrus() *logrus.Logger

		// GetLevel
		// Deprecated. Stop using direct logrus structures.
		GetLevel() logrus.Level
	}

	Logger interface {
		LegacyLogger
		RawLogger
		IsLegacyFormatter() bool
	}

	CancelFn func()
)

func newRawLog() *logrus.Logger {
	var l = logrus.New()
	l.SetFormatter(&RawFormatter{})
	return l
}

func newEmergencyLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr)
	l.SetFormatter(&logrus.TextFormatter{})
	return l
}

func newTmpLogger(tmpLoggerHook *tmpLogsCollector, emergencyLogger *logrus.Logger) *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.AddHook(tmpLoggerHook)
	l.ExitFunc = func(code int) {
		tmpLoggerHook.Proxy(emergencyLogger)
		os.Exit(code)
	}
	return l
}

// RawFormatter returns the logrus entry message as bytes.
type RawFormatter struct{}

// Format returns the entry.Message as a []byte.
func (f *RawFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

func Setup(f func(b *Builder)) {
	once.Must(func() {
		var builder Builder
		f(&builder)
		logger := builder.BuildAndPropagate()

		log = &loggerWrapper{logger}
		tmpLoggerHook.Proxy(logger)
	})
}

func Flush() {
	once.Do(func(executed bool) {
		logger := log.Logger

		// logger was not initialized for unknown reason
		// flush logs to stderr logger just to inform what happened in program
		if !executed {
			logger = emergencyLogger
		}

		tmpLoggerHook.Proxy(logger)
	})
}

// Reset state to default.
// Added to pass tests.
func Reset() CancelFn {
	return once.reset(false)
}

// Get returns the default configured logger.
func Get() Logger {
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

// todo: remove and put into method
func isLegacyFormatter(formatter logrus.Formatter) bool {
	textFormatter, ok := formatter.(*logrus.TextFormatter)
	return ok && textFormatter.TimestampFormat == LegacyTimestampFormat
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

type invokeOnce struct {
	mu    sync.Mutex
	value bool
}

func (s *invokeOnce) Must(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.value {
		panic("doOnce.Must has to be executed only once")
	}

	s.value = true

	fn()
}

func (s *invokeOnce) Do(fn func(executed bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.value)
}

// reset's value of invoke once runner
// create for testing purposes
func (s *invokeOnce) reset(value bool) func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldValue := s.value
	s.value = value

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.value = oldValue
	}
}

var _ logrus.Hook = new(tmpLogsCollector)

type tmpLogsCollector struct {
	mu      sync.Mutex
	entries []*logrus.Entry
}

func (e *tmpLogsCollector) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (e *tmpLogsCollector) Fire(entry *logrus.Entry) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entries = append(e.entries, entry)
	return nil
}

func (e *tmpLogsCollector) Proxy(logger *logrus.Logger) {
	e.mu.Lock()
	localEntries := e.entries
	e.entries = nil
	e.mu.Unlock()

	for _, entry := range localEntries {
		clonedEntry := logger.WithFields(entry.Data)
		clonedEntry.Time = entry.Time
		clonedEntry.Log(entry.Level, entry.Message)
	}
}

func CoalesceEnv[T any, P interface {
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

func CoalesceEnvOrDefault[T any, P interface {
	*T
	Parse(string) bool
	Valid() bool
}](default_ T, fallback T, envNames ...string) T {

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

	if P(&fallback).Valid() {
		return fallback
	}

	return default_
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

func Wrap(log *logrus.Logger) Logger {
	return &loggerWrapper{Logger: log}
}

type loggerWrapper struct{ *logrus.Logger }

func (d *loggerWrapper) NewEntry() *logrus.Entry {
	return logrus.NewEntry(d.Logger)
}

func (d *loggerWrapper) AsLogrus() *logrus.Logger {
	return d.Logger
}

func (d *loggerWrapper) IsLegacyFormatter() bool {
	return isLegacyFormatter(d.Formatter)
}

func defaultFieldMap() logrus.FieldMap {
	return logrus.FieldMap{
		logrus.FieldKeyMsg: "message",
	}
}
