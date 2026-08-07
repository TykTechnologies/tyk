package oauth2common

import (
	"net/http"
	"time"

	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
)

// MaxIdPResponseBytes caps the response body read from the IdP to prevent memory abuse.
const MaxIdPResponseBytes = 1 << 20

// NewIdPHTTPClient returns an HTTP client for IdP calls with the given timeout.
// The transport is wrapped so that, when the request carries an active span,
// the IdP round-trip is emitted as a child client span — present on a cache
// miss, absent on a cache hit (which never builds a request). When tracing is
// disabled the wrap is a cheap no-op. The wrapper suppresses otelhttp's
// auto-emitted HTTP-client metrics — Tyk owns its own metric instrumentation
// for the exchange.
func NewIdPHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: tyktrace.NewHTTPTransport(http.DefaultTransport),
	}
}
