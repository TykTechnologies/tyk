package request

import (
	"net"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

var Global func() config.Config

// RealIP takes a request object, and returns the real Client IP address.
func RealIP(r *http.Request) string {

	if contextIp := r.Context().Value("remote_addr"); contextIp != nil {
		return contextIp.(string)
	}

	if realIPVal := r.Header.Get(header.XRealIP); realIPVal != "" {
		if realIP := net.ParseIP(realIPVal); realIP != nil {
			return realIP.String()
		}
	}

	if fw := r.Header.Get(header.XForwardFor); fw != "" {
		xffs := strings.Split(fw, ",")

		// If no IPs, return the first IP in the chain
		if len(xffs) == 0 {
			return ""
		}

		// Get depth from config, default to 0 (first IP in chain)
		depth := 0
		if Global != nil {
			depth = Global().HttpServerOptions.XFFDepth
		}

		// If depth exceeds available IPs, return empty
		if depth > len(xffs) {
			return ""
		}

		// Choose the appropriate IP based on depth
		// depth=0 means first IP (leftmost), depth=1 means last IP, depth=2 means second to last, etc.
		var ip string
		if depth == 0 {
			ip = strings.TrimSpace(xffs[0])
		} else {
			ip = strings.TrimSpace(xffs[len(xffs)-depth])
		}

		// Validate that the IP is properly formatted before returning it
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return parsedIP.String()
		}
		// If IP is invalid, fall through to use RemoteAddr
	}

	// From net/http.Request.RemoteAddr:
	//   The HTTP server in this package sets RemoteAddr to an
	//   "IP:port" address before invoking a handler.
	// So we can ignore the case of the port missing.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
