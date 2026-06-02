package log

import (
	"errors"
	"io"

	"github.com/sirupsen/logrus"
)

type Sink interface {
	io.Writer
	logrus.Formatter
	Acceptor
}

type Acceptor interface {
	Accept(entry *logrus.Entry) bool
}

func NewSink(
	writer io.Writer,
	formatter logrus.Formatter,
	acceptor Acceptor,
) Sink {

	return &anonSink{
		Writer:    writer,
		Formatter: formatter,
		Acceptor:  acceptor,
	}
}

type anonSink struct {
	io.Writer
	logrus.Formatter
	Acceptor
}

type multiSinkHook struct {
	sinks []Sink
}

func (h *multiSinkHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *multiSinkHook) Fire(entry *logrus.Entry) error {
	var res []error

	for _, s := range h.sinks {
		if !s.Accept(entry) {
			continue
		}

		serialized, err := s.Format(entry)
		if err != nil {
			res = append(res, err)
			continue
		}

		if _, err = s.Write(serialized); err != nil {
			res = append(res, err)
		}
	}

	return errors.Join(res...)
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
