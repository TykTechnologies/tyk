package httputil

import (
	"net/http"

	"github.com/TykTechnologies/tyk/header"
)

// TransferEncoding gets the header value from the request.
// SW-REQ-158
func TransferEncoding(req *http.Request) string {
	for _, val := range req.TransferEncoding {
		if val != "" {
			return val
		}
	}
	return ""
}

// HasTransferEncoding returns true if a transfer encoding header is present.
// SW-REQ-158
func HasTransferEncoding(req *http.Request) bool {
	return TransferEncoding(req) != ""
}

// RequestScheme returns the scheme of the request. It checks the X-Forwarded-Proto
// header first, then falls back to the TLS connection state.
// SW-REQ-158
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
// SW-REQ-158
func IsCORSPreflightRequest(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}
