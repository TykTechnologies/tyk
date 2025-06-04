//go:build !ee && !dev

package gateway

import (
	"net/http"
)

func getUpstreamBasicAuthMw(base *BaseMiddleware) TykMiddleware {
	return &noopUpstreamBasicAuth{base}
}

type noopUpstreamBasicAuth struct {
	*BaseMiddleware
}

// ProcessRequest is noop implementation for upstream basic auth mw.
func (d *noopUpstreamBasicAuth) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	return nil, http.StatusOK
}

// EnabledForSpec will always return false for noopUpstreamBasicAuth.
func (d *noopUpstreamBasicAuth) EnabledForSpec() bool {
	if d.Spec.UpstreamAuth.BasicAuth.Enabled {
		d.Logger().Error("Upstream basic auth is supported only in Tyk Enterprise Edition")
	}

	return false
}

// Name returns the name of the mw.
func (d *noopUpstreamBasicAuth) Name() string {
	return "NooPUpstreamBasicAuth"
}
