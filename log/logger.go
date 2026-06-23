package log

import (
	"io"
	"os"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

type (
	innerLogger = logrus.Logger

	Logger struct {
		*innerLogger
		tmpLogsCollector *tmpLogsCollector
		setupOnce        invokeOnce
		emergencyLogger  *logrus.Logger
		OsExit           func(int)
		logFormat        Format
	}

	CancelFn func()

	nonImplementable interface {
		nonImplementable()
	}
)

func New() *Logger {
	emergencyLogger := newEmergencyLogger()

	inner := logrus.New()
	tmpLogs := &tmpLogsCollector{}

	inner.SetFormatter(&dummyFormatter{})
	inner.SetLevel(logrus.TraceLevel)
	inner.SetOutput(io.Discard)

	lgr := &Logger{
		OsExit:           os.Exit,
		emergencyLogger:  emergencyLogger,
		innerLogger:      inner,
		tmpLogsCollector: tmpLogs,
	}

	inner.ExitFunc = func(code int) {
		lgr.setupOnce.Do(func(executed bool) {
			if executed {
				tmpLogs.Forward(inner)
			} else {
				// send logs to emergency logger in case if Fatal was called
				tmpLogs.Forward(emergencyLogger)
			}
		})

		lgr.ExitFunc(code)
	}

	lgr.AddHook(tmpLogs)

	return lgr
}

func NewNullLogger() (*Logger, *Hook) {
	rawLogger, hook := logrustest.NewNullLogger()

	lgr := New()
	lgr.Setup(func(_ *Builder) {})

	lgr.innerLogger = rawLogger

	return lgr, NewHook(hook)
}

func (l *Logger) IsLegacyFormatter() bool {
	return l.logFormat == FormatLegacy
}

func (l *Logger) NewEntry() *logrus.Entry {
	return logrus.NewEntry(l.innerLogger)
}

func (l *Logger) AsLogrus() *logrus.Logger {
	return l.innerLogger
}

func (l *Logger) RemoveHook(hookToRemove logrus.Hook) {
	newHooks := make(logrus.LevelHooks, len(l.Hooks))

	for level, hooks := range l.Hooks {
		for _, h := range hooks {
			if h != hookToRemove {
				newHooks[level] = append(newHooks[level], h)
			}
		}
	}

	l.ReplaceHooks(newHooks)
}

func (l *Logger) Setup(f func(b *Builder)) {
	l.setupOnce.MustOnce(func() {
		var builder Builder
		f(&builder)
		logger := builder.BuildAndPropagate()

		l.innerLogger = logger
		l.logFormat = builder.logFormat
		l.tmpLogsCollector.Forward(logger)
	})
}

func (l *Logger) Flush() {
	l.setupOnce.Do(func(executed bool) {
		logger := l.innerLogger

		if !executed {
			logger = l.emergencyLogger
		}

		l.tmpLogsCollector.Forward(logger)
	})
}

// GetTestHook bind to global logger in during the test.
func (l *Logger) GetTestHook(t *testing.T) *Hook {
	t.Helper()

	var hook = NewHook(nil)
	l.AddHook(hook)

	t.Cleanup(func() {
		l.RemoveHook(hook)
	})

	return hook
}

// SetFormatter
// Deprecated. Stop using direct logrus structures.
// Shadowed.
func (l *Logger) SetFormatter(_ nonImplementable) {}

// SetOutput
// Deprecated. Stop using direct logrus structures.
// Shadowed.
func (l *Logger) SetOutput(_ nonImplementable) {}

// Reset state to default.
// Added to pass tests.
func (l *Logger) Reset() CancelFn {
	return l.setupOnce.reset(false)
}

type invokeOnce struct {
	mu    sync.Mutex
	value bool
}

func (s *invokeOnce) MustOnce(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.value {
		panic("invokeOnce.Must has to be executed only once")
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
func (s *invokeOnce) reset(value bool) CancelFn {
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

func (e *tmpLogsCollector) Forward(dest *logrus.Logger) {
	e.mu.Lock()
	localEntries := e.entries
	e.entries = nil
	e.mu.Unlock()

	for _, entry := range localEntries {
		entry.Logger = dest // replace logger to make  copied entries write to proper place

		clonedEntry := dest.WithFields(entry.Data)
		clonedEntry.Time = entry.Time
		clonedEntry.Log(entry.Level, entry.Message)
	}
}

func newEmergencyLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr)
	l.SetFormatter(&logrus.TextFormatter{})
	l.SetLevel(logrus.TraceLevel)
	return l
}
