package errors

import "io"

type ResponseWriter interface {
	WriteResponse(writer io.Writer) (n int, err error)
}
