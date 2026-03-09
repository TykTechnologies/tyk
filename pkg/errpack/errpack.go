package errpack

import (
	"fmt"

	"github.com/TykTechnologies/tyk/internal/errors"
)

var (
	TypeUnknown        = Type{typ: "unknown"}
	TypeDomain         = Type{typ: "domain"}
	TypeApp            = Type{typ: "app"}
	TypeInfrastructure = Type{typ: "infrastructure"}
	TypeNotFound       = Type{typ: "notfound"}
	BrokenInvariant    = Type{typ: "broken-invariant"}
)

var (
	MsgNotFound = "entry not found"
)

type Type struct {
	typ string
}

type Error struct {
	msg  string
	prev error
	typ  Type
}

type Option func(*Error)

func New(msg string, opts ...Option) Error {
	err := Error{msg: msg, typ: TypeUnknown}

	for _, op := range opts {
		op(&err)
	}

	return err
}

func (e Error) Error() string {
	if e.prev == nil {
		return e.msg
	}

	return fmt.Sprintf("%s: %s", e.msg, e.prev.Error())
}

func (e Error) Is(err error) bool {
	var errp Error
	return errors.As(err, errp) && errp.typ == e.typ && errp.msg == e.msg
}

// Chain sets error predecessor
func (e Error) Chain(err error) Error {
	e.prev = err
	return e
}

func (e Error) TypeOf(typ Type) bool {
	return e.typ == typ
}

func Domain(msg string) Error {
	return New(msg, WithType(TypeDomain))
}

func Domainf(format string, a ...any) Error {
	err := fmt.Errorf(format, a...)

	return Error{
		msg:  err.Error(),
		typ:  TypeDomain,
		prev: err,
	}
}

func Infra(msg string) Error {
	return New(msg, WithType(TypeInfrastructure))
}

func Application(msg string) Error {
	return New(msg, WithType(TypeApp))
}

func NotFoundWithId(identifier string) Error {
	return New(fmt.Sprintf(`%s: "%s"`, MsgNotFound, identifier), WithType(TypeNotFound))
}

func WithType(typ Type) Option {
	return func(e *Error) {
		e.typ = typ
	}
}
