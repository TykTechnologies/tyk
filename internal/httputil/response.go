package httputil

import (
	"net/http"
)

// EntityTooLarge responds with HTTP 413 Request Entity Too Large.
// The function is used for a response when blocking requests by size.
func EntityTooLarge(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusRequestEntityTooLarge
	http.Error(w, http.StatusText(status), status)
}

// LengthRequired responds with HTTP 411 Length Required.
// The function is used in places where Content-Length is required.
func LengthRequired(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusLengthRequired
	http.Error(w, http.StatusText(status), status)
}
