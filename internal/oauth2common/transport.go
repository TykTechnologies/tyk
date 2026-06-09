package oauth2common

import (
	"net/http"
	"time"
)

// MaxIdPResponseBytes caps the response body read from the IdP to prevent memory abuse.
const MaxIdPResponseBytes = 1 << 20

// NewIdPHTTPClient returns an HTTP client for IdP calls with the given timeout.
func NewIdPHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: http.DefaultTransport,
	}
}
