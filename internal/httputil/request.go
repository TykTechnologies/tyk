package httputil

import (
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/header"
)

// TransferEncoding gets the header value from the request.
func TransferEncoding(req *http.Request) string {
	for _, val := range req.TransferEncoding {
		if val != "" {
			return val
		}
	}
	return ""
}

// HasTransferEncoding returns true if a transfer encoding header is present.
func HasTransferEncoding(req *http.Request) bool {
	return TransferEncoding(req) != ""
}

// RequestScheme returns the scheme of the request. It checks the X-Forwarded-Proto
// header first, then falls back to the TLS connection state.
func RequestScheme(r *http.Request) string {
	if proto := r.Header.Get(header.XForwardProto); proto != "" {
		return proto
	}
	if r.TLS == nil {
		return "http"
	}
	return "https"
}

// IsCORSPreflightRequest function determines if an HTTP request is a CORS preflight request.
// It returns true if the request's method is OPTIONS and the Access-Control-Request-Method header is present
// and not empty, which are the conditions for a standard preflight request. Otherwise, it returns false.
func IsCORSPreflightRequest(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// ForwardedScheme returns the scheme the client used to reach the Gateway.
// Behind a TLS-terminating proxy the connection is plain HTTP, so the last
// X-Forwarded-Proto hop is used when it is "http" or "https". Any other value
// is ignored and the TLS state of the connection decides.
func ForwardedScheme(r *http.Request) string {
	values := r.Header.Values(header.XForwardProto)
	if len(values) > 0 {
		hops := strings.Split(values[len(values)-1], ",")
		switch scheme := strings.ToLower(strings.TrimSpace(hops[len(hops)-1])); scheme {
		case "http", "https":
			return scheme
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
