package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

type Sinker interface {
	Sink(e *logrus.Entry)
}

type Acceptor interface {
	Accept(entry *logrus.Entry) bool
}

func NewSink(
	writer io.Writer,
	formatter logrus.Formatter,
	acceptor Acceptor,
) *Sink {

	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)
	logger.SetFormatter(formatter)
	logger.SetOutput(writer)
	logger.ExitFunc = func(_ int) {} // skip exit in sub-loggers (sinks)

	return &Sink{
		logger:   logger,
		acceptor: acceptor,
	}
}

type Sink struct {
	logger   *logrus.Logger
	acceptor Acceptor
}

func (a *Sink) Sink(entry *logrus.Entry) {
	if !a.acceptor.Accept(entry) {
		return
	}

	clonedEntry := a.logger.WithFields(entry.Data)
	clonedEntry.Time = entry.Time
	clonedEntry.Log(entry.Level, entry.Message)
}

type multiSinkHook struct {
	sinks []Sinker
}

func (h *multiSinkHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *multiSinkHook) Fire(entry *logrus.Entry) error {
	for _, s := range h.sinks {
		s.Sink(entry)
	}

	return nil
}

// AcceptorFn
// Anonymous filter/acceptor.
// Normally log levels are trace < debug < info < warn < error.
// But logrus has reverted logic trace > debug > info > warn > error.
// Ensure you have provided the proper predicate.
type AcceptorFn func(e *logrus.Entry) bool

func (fn AcceptorFn) Accept(entry *logrus.Entry) bool {
	return fn(entry)
}

func NewAcceptorGte(level logrus.Level) Acceptor {
	return AcceptorFn(func(e *logrus.Entry) bool {
		return e.Level <= level
	})
}

func NewAcceptorLt(level logrus.Level) Acceptor {
	return AcceptorFn(func(e *logrus.Entry) bool {
		return e.Level > level
	})
}

var (
	AcceptorAllowAll = AcceptorFn(func(_ *logrus.Entry) bool {
		return true
	})
)
