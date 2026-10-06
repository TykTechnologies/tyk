package errors

import "net/http"

type ToResponseWriter interface {
	WriteToResponse(w http.ResponseWriter, statusCode int) error
}
