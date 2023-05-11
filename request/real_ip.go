package request

import (
	"net"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/headers"
)

// RealIP takes a request object, and returns the real Client IP address.
func RealIP(r *http.Request) string {

	if contextIp := r.Context().Value("remote_addr"); contextIp != nil {
		return contextIp.(string)
	}

<<<<<<< HEAD
	if realIP := r.Header.Get(headers.XRealIP); realIP != "" {
		return realIP
=======
	if realIPVal := r.Header.Get(header.XRealIP); realIPVal != "" {
		if realIP := net.ParseIP(realIPVal); realIP != nil {
			return realIP.String()
		}
>>>>>>> 35e1d3f2... [TT-2949] add validation for allowedIPs and blacklisted IPs when enabled (#4998)
	}

	if fw := r.Header.Get(headers.XForwardFor); fw != "" {
		// X-Forwarded-For has no port
		if i := strings.IndexByte(fw, ','); i >= 0 {
			fw = fw[:i]
		}

		if fwIP := net.ParseIP(fw); fwIP != nil {
			return fwIP.String()
		}
	}

	// From net/http.Request.RemoteAddr:
	//   The HTTP server in this package sets RemoteAddr to an
	//   "IP:port" address before invoking a handler.
	// So we can ignore the case of the port missing.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
