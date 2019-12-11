package graylog

import (
	"encoding/json"
	"runtime"

	"github.com/pkg/errors"
)

// newMarshalableError builds an error which encodes its error message into JSON
func newMarshalableError(err error) *marshalableError {
	return &marshalableError{err}
}

// a marshalableError is an error that can be encoded into JSON
type marshalableError struct {
	err error
}

// MarshalJSON implements json.Marshaler for marshalableError
func (m *marshalableError) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.err.Error())
}

type causer interface {
	Cause() error
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func extractStackTrace(err error) errors.StackTrace {
	var tracer stackTracer
	for {
		if st, ok := err.(stackTracer); ok {
			tracer = st
		}
		if cause, ok := err.(causer); ok {
			err = cause.Cause()
			continue
		}
		break
	}
	if tracer == nil {
		return nil
	}
	return tracer.StackTrace()
}

func extractFileAndLine(stacktrace errors.StackTrace) (string, int) {
	pc := uintptr(stacktrace[0])
	fn := runtime.FuncForPC(pc)
	return fn.FileLine(pc)
}
