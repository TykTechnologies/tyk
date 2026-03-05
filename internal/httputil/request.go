package httputil

import (
	"net/http"

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
