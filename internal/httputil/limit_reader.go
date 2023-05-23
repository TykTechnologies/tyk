package httputil

import (
	"errors"
	"io"
	"net/http"
)

// LimitReader replaces the request body with a reader designed to
// error out when the size limit has been exceeded.
func LimitReader(r *http.Request, limit int64) {
	r.Body = &limitedRequestBody{
		body:  r.Body,
		limit: limit,
		err:   nil,
	}
}

type limitedRequestBody struct {
	body  io.Reader
	limit int64
	err   error
}

func (l *limitedRequestBody) Read(p []byte) (n int, err error) {
	n, err = l.body.Read(p)
	if l.err != nil {
		return n, l.err
	}

	if n > 0 {
		l.limit -= int64(n)
		if l.limit < 0 {
			l.err = errors.New("request entity too large")
			return n, http.ErrBodyNotAllowed
		}
	}

	return n, err
}

func (l *limitedRequestBody) Close() error {
	l.err = nil
	return nil
}
