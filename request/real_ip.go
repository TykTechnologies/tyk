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
		// Handle case where ALB or proxy adds port to IP (e.g., "192.168.1.1:8080")
		ip := realIPVal
		if host, _, err := net.SplitHostPort(realIPVal); err == nil {
			ip = host
		}

		if realIP := net.ParseIP(ip); realIP != nil {
			return realIP.String()
		}
	}

	if fw := r.Header.Get(header.XForwardFor); fw != "" {
		xffs := strings.Split(fw, ",")

		// Get depth from config, default to 0 (first IP in chain)
		var depth int
		if Global != nil {
			depth = Global().HttpServerOptions.XFFDepth
		}

		// The following check for invalid depth configs.
		// It's more secure to return empty if depth is invalid.
		// Defaulting to an IP from the request would be
		// burying a configuration failure.
		if depth < 0 || depth > len(xffs) {
			return ""
		}

		// Choose the appropriate IP based on depth
		// depth=0 means first IP (leftmost), depth=1 means last IP, depth=2 means second to last, etc.
		// Negative depth is invalid and treated same as 0/unset.
		var ip string
		if depth == 0 {
			ip = strings.TrimSpace(xffs[0])
		} else {
			ip = strings.TrimSpace(xffs[len(xffs)-depth])
		}

		// Handle case where ALB or proxy adds port to IP (e.g., "192.168.1.1:8080")
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
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
