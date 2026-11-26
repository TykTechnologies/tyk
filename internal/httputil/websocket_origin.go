package httputil

import (
	"net/http"
	"net/netip"

	"github.com/rs/cors"
)

// WebSocketOriginOptions configures a WebSocketOriginChecker.
type WebSocketOriginOptions struct {
	// AllowAnyOrigin turns the check off and accepts every origin.
	AllowAnyOrigin bool
	// CORSEnabled reports whether the API's CORS settings are on.
	CORSEnabled bool
	// AllowedOrigins holds the API's CORS allowed origins. Wildcards are
	// matched as Tyk's CORS middleware matches them.
	AllowedOrigins []string
	// TrustedProxyCIDRs lists the proxies whose forwarded headers name the
	// Gateway's public origin.
	TrustedProxyCIDRs []string
}

// WebSocketOriginChecker decides whether a WebSocket handshake may proceed
// based on its Origin header. Browsers don't apply CORS to WebSocket
// handshakes, so this check is the server's protection against cross-site
// WebSocket hijacking.
type WebSocketOriginChecker struct {
	allowAnyOrigin bool
	trustedProxies []netip.Prefix
	// cors is nil when the API's CORS settings are off.
	cors *cors.Cors
}

// NewWebSocketOriginChecker builds a checker from opts.
func NewWebSocketOriginChecker(opts WebSocketOriginOptions) (*WebSocketOriginChecker, error) {
	trustedProxies, err := ParseTrustedProxyCIDRs(opts.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	checker := &WebSocketOriginChecker{
		allowAnyOrigin: opts.AllowAnyOrigin,
		trustedProxies: trustedProxies,
	}
	if opts.CORSEnabled {
		// Same origin matching as gateway.CORSMiddleware, so a WebSocket
		// handshake is allowed from exactly the origins HTTP requests are.
		checker.cors = cors.New(cors.Options{AllowedOrigins: opts.AllowedOrigins})
	}
	return checker, nil
}

// Allowed reports whether the handshake in r may proceed. A handshake with no
// Origin header is allowed, because browsers always send one. Otherwise the
// origin must be the Gateway's own origin or one the API's CORS settings allow.
func (c *WebSocketOriginChecker) Allowed(r *http.Request) bool {
	if c.allowAnyOrigin {
		return true
	}

	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}

	origin, err := CanonicalOrigin(values[0])
	if err != nil {
		return false
	}

	if own, err := ExternalOriginWithTrustedProxies(r, c.trustedProxies); err == nil && origin == own {
		return true
	}

	return c.cors != nil && c.cors.OriginAllowed(r)
}
