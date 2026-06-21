package httputil

import (
	"net/http"
)

// EntityTooLarge responds with HTTP 413 Request Entity Too Large.
// The function is used for a response when blocking requests by size.
// SW-REQ-158
func EntityTooLarge(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusRequestEntityTooLarge
	http.Error(w, http.StatusText(status), status)
}

// LengthRequired responds with HTTP 411 Length Required.
// The function is used in places where Content-Length is required.
// SW-REQ-158
func LengthRequired(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusLengthRequired
	http.Error(w, http.StatusText(status), status)
}

// InternalServerError responds with HTTP 500 Internal Server Error.
// SW-REQ-158
func InternalServerError(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusInternalServerError
	http.Error(w, http.StatusText(status), status)
}

// RemoveResponseTransferEncoding will remove a transfer encoding hint from the response.
// SW-REQ-158
func RemoveResponseTransferEncoding(response *http.Response, victim string) {
	for i, value := range response.TransferEncoding {
		if value == victim {
			response.TransferEncoding = append(response.TransferEncoding[:i], response.TransferEncoding[i+1:]...)
		}
	}
}
