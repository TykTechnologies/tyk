package gateway

import (
	"net/http"

	"github.com/sirupsen/logrus"

	internalhttputil "github.com/TykTechnologies/tyk/internal/httputil"
)

// webSocketOriginAllowed reports whether a WebSocket handshake to the API may
// proceed, and logs each refusal. Browsers don't apply CORS to WebSocket
// handshakes, so the Origin header is the only protection against another
// website reading the API through a visitor's browser.
func (spec *APISpec) webSocketOriginAllowed(r *http.Request) bool {
	// A checker error means the API's origin settings can't be parsed, so
	// refuse every handshake rather than guess. Startup already rejects invalid
	// trusted_proxy_cidrs, so this isn't expected in practice.
	checker, err := spec.webSocketOriginChecker()
	if err == nil && checker.Allowed(r) {
		return true
	}

	entry := log.WithFields(logrus.Fields{
		"prefix": "websocket",
		"api_id": spec.APIID,
		"origin": r.Header.Get("Origin"),
	})
	if err != nil {
		entry = entry.WithError(err)
	}
	entry.Warn("WebSocket handshake refused: origin is not the Gateway's own origin and not in the API's CORS allowed origins")
	return false
}

// webSocketOriginChecker builds the API's checker once. A loaded spec's CORS
// and Gateway settings don't change, so the result is reused for every
// handshake.
func (spec *APISpec) webSocketOriginChecker() (*internalhttputil.WebSocketOriginChecker, error) {
	spec.webSocketOriginOnce.Do(func() {
		spec.webSocketOrigin, spec.webSocketOriginErr = internalhttputil.NewWebSocketOriginChecker(internalhttputil.WebSocketOriginOptions{
			AllowAnyOrigin:    spec.GlobalConfig.AllowUnsafeWebSocketOrigin,
			CORSEnabled:       spec.CORS.Enable,
			AllowedOrigins:    spec.CORS.AllowedOrigins,
			TrustedProxyCIDRs: spec.GlobalConfig.HttpServerOptions.TrustedProxyCIDRs,
		})
	})
	return spec.webSocketOrigin, spec.webSocketOriginErr
}
