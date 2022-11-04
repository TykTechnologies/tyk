package request

import (
	"net"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/header"
)

// RealIP takes a request object, and returns the real Client IP address.
func RealIP(r *http.Request) string {

	if contextIp := r.Context().Value("remote_addr"); contextIp != nil {
		return contextIp.(string)
	}

	if realIP := r.Header.Get(header.XRealIP); realIP != "" {
		return realIP
	}

	if fw := r.Header.Get(header.XForwardFor); fw != "" {
		// X-Forwarded-For has no port
		if i := strings.IndexByte(fw, ','); i >= 0 {

			return fw[:i]
		}

		return fw
	}

	// From net/http.Request.RemoteAddr:
	//   The HTTP server in this package sets RemoteAddr to an
	//   "IP:port" address before invoking a handler.
	// So we can ignore the case of the port missing.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
