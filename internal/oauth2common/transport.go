package oauth2common

import (
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// MaxIdPResponseBytes caps the response body read from the IdP to prevent memory abuse.
const MaxIdPResponseBytes = 1 << 20

// NewIdPHTTPClient returns an HTTP client for IdP calls with the given timeout.
// The transport is wrapped with otelhttp so that, when the request carries an
// active span, the IdP round-trip is emitted as a child client span — present
// on a cache miss, absent on a cache hit (which never builds a request). When
// tracing is disabled the wrap is a cheap no-op.
func NewIdPHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return "oauth2.idp " + r.Method
			}),
		),
	}
}
