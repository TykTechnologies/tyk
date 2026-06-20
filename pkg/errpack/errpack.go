package errpack

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/errors"
)

var (
	// SW-REQ-066
	TypeUnknown        = Type{typ: "unknown"}
	TypeDomain         = Type{typ: "domain"}
	TypeApp            = Type{typ: "app"}
	TypeInfrastructure = Type{typ: "infrastructure"}
	TypeNotFound       = Type{typ: "notfound"}
	BrokenInvariant    = Type{typ: "broken-invariant"}
)

var (
	// SW-REQ-066
	MsgNotFound = "entry not found"
)

// SW-REQ-066
type Type struct {
	typ string
}

// SW-REQ-066
type Error struct {
	msg      string
	prev     error
	typ      Type
	logLevel logLevel
}

type logLevel struct {
	level   logrus.Level
	defined bool
}

// SW-REQ-066
type Option func(*Error)

// SW-REQ-066
func New(msg string, opts ...Option) Error {
	err := Error{msg: msg, typ: TypeUnknown}

	for _, op := range opts {
		op(&err)
	}

	return err
}

// SW-REQ-066
func Wrap(err error, opts ...Option) error {
	if err == nil {
		return nil
	}

	e := Error{msg: err.Error(), typ: TypeUnknown, prev: err}

	for _, op := range opts {
		op(&e)
	}

	return e
}

// SW-REQ-066
func (e Error) Error() string {
	return e.msg
}

// SW-REQ-066
func (e Error) Is(err error) bool {
	var errp Error
	return errors.As(err, &errp) && errp.typ == e.typ && errp.msg == e.msg && errp.prev == e.prev
}

// SW-REQ-066
func (e Error) Unwrap() error {
	return e.prev
}

// SW-REQ-066
// Chain sets error predecessor
func (e Error) Chain(err error) Error {
	e.prev = err
	return e
}

// SW-REQ-066
func (e Error) TypeOf(typ Type) bool {
	return e.typ == typ
}

// SW-REQ-066
func Domain(msg string) Error {
	return New(msg, WithType(TypeDomain))
}

// SW-REQ-066
func Domainf(format string, a ...any) Error {
	err := fmt.Errorf(format, a...)

	return Error{
		msg:  err.Error(),
		typ:  TypeDomain,
		prev: err,
	}
}

// SW-REQ-066
func Infra(msg string) Error {
	return New(msg, WithType(TypeInfrastructure))
}

// SW-REQ-066
func Application(msg string) Error {
	return New(msg, WithType(TypeApp))
}

// SW-REQ-066
func NotFoundWithId(identifier string) Error {
	return New(fmt.Sprintf(`%s: "%s"`, MsgNotFound, identifier), WithType(TypeNotFound))
}

// SW-REQ-066
func WithType(typ Type) Option {
	return func(e *Error) {
		e.typ = typ
	}
}

// SW-REQ-066
func WithLogLevel(level logrus.Level) Option {
	return func(e *Error) {
		e.logLevel = logLevel{defined: true, level: level}
	}
}

// SW-REQ-066
func LogLevel(err error, fallback logrus.Level) logrus.Level {
	var errPtr Error

	if errors.As(err, &errPtr) && errPtr.logLevel.defined {
		return errPtr.logLevel.level
	}

	return fallback
}
