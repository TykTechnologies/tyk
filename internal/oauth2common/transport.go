package oauth2common

import (
	"net/http"
	"net/url"
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

// SetFormEncodedBasicAuth sets RFC 6749 §2.3.1 client authentication on an IdP
// request. The spec requires the client id and secret to be form-urlencoded
// before being base64-encoded, which a compliant IdP form-decodes on receipt.
// http.Request.SetBasicAuth omits that step, so a credential containing "+",
// "%" or ":" is transmitted in a form a compliant IdP decodes to a different
// value — authentication then fails for a correctly configured provider. The
// encoding is a no-op for the alphanumeric credentials most IdPs issue.
func SetFormEncodedBasicAuth(req *http.Request, clientID, clientSecret string) {
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
}
