package errpack

import "fmt"

type Error struct {
	msg  string
	prev error
}

func (e Error) Error() string {
	if e.prev == nil {
		return e.msg
	}

	return fmt.Sprintf("%s: %s", e.msg, e.prev.Error())
}

func Wrap(err error, msg string) Error {
	return Error{msg: msg, prev: err}
}
