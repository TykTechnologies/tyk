package log

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

type (
	innerLogger = logrus.Logger

	Logger struct {
		*innerLogger
		tmpLogsCollector       *tmpLogsCollector
		setupOnce              invokeOnce
		emergencyLogger        *logrus.Logger
		osExit                 func(int)
		legacyLogFormatEnabled bool
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
		osExit:           os.Exit,
		emergencyLogger:  emergencyLogger,
		innerLogger:      inner,
		tmpLogsCollector: tmpLogs,
	}

	inner.ExitFunc = func(code int) {
		lgr.Flush()
		lgr.osExit(code)
	}

	lgr.AddHook(tmpLogs)

	return lgr
}

func Build(factory func(b *Builder)) *Logger {
	l := New()
	l.Setup(factory)
	return l
}

func NewNullLogger() (*Logger, *Hook) {
	rawLogger, hook := logrustest.NewNullLogger()

	lgr := New()
	lgr.Setup(func(_ *Builder) {})

	lgr.innerLogger = rawLogger

	return lgr, NewHook(hook)
}

// Reset state to default.
// Added to pass tests.
func (l *Logger) Reset() CancelFn {
	return l.setupOnce.reset()
}

func (l *Logger) IsLegacyFormatterEnabled() bool {
	return l.legacyLogFormatEnabled
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
		builder.buildAndPropagate(l)

		l.RemoveHook(l.tmpLogsCollector)
		l.tmpLogsCollector.Forward(l.innerLogger)
	})
}

func (l *Logger) Flush() {
	if l.setupOnce.IsReady() {
		l.tmpLogsCollector.Forward(l.innerLogger)
	} else {
		l.tmpLogsCollector.Forward(l.emergencyLogger)
	}
}

// GetTestHook bind to global logger in during the test.
func (l *Logger) GetTestHook(t *testing.T) *Hook {
	t.Helper()

	var hook = NewHook(nil)
	l.AddHook(hook)

	oLevel := l.GetLevel()
	l.innerLogger.SetLevel(logrus.TraceLevel)

	t.Cleanup(func() {
		l.RemoveHook(hook)
		l.innerLogger.SetLevel(oLevel)
	})

	return hook
}

func (l *Logger) SetTestLogLevel(t *testing.T, level logrus.Level) {
	t.Helper()

	oLevel := l.GetLevel()
	l.innerLogger.SetLevel(level)

	t.Cleanup(func() {
		l.innerLogger.SetLevel(oLevel)
	})
}

// SetFormatter
// Deprecated. Stop using direct logrus structures.
// Shadowed.
func (l *Logger) SetFormatter(_ nonImplementable) {}

// SetOutput
// Deprecated. Stop using direct logrus structures.
// Shadowed.
func (l *Logger) SetOutput(_ nonImplementable) {}

// SetLevel
// Deprecated. Stop using direct logrus structures.
// Shadowed.
func (l *Logger) SetLevel(_ nonImplementable) {}

const (
	statePending      uint32 = 0
	stateInitializing uint32 = 1
	stateReady        uint32 = 2
)

type invokeOnce struct {
	state atomic.Uint32
}

func (s *invokeOnce) MustOnce(fn func()) {
	if !s.state.CompareAndSwap(statePending, stateInitializing) {
		panic("invokeOnce.MustOnce has to be executed only once")
	}

	fn()

	s.state.Store(stateReady)
}

func (s *invokeOnce) IsReady() bool {
	return s.state.Load() == stateReady
}

// reset's value of invoke once runner
// create for testing purposes
func (s *invokeOnce) reset() CancelFn {
	var once sync.Once
	oldValue := s.state.Load()
	s.state.Store(statePending)

	return func() {
		once.Do(func() {
			s.state.Store(oldValue)
		})
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
