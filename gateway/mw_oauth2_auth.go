//go:build !ee && !dev

package gateway

import (
	"net/http"
)

func getUpstreamOAuthMw(base *BaseMiddleware) TykMiddleware {
	return &noopUpstreamOAuth{base}
}

type noopUpstreamOAuth struct {
	*BaseMiddleware
}

// ProcessRequest is noop implementation for upstream OAuth mw.
func (d *noopUpstreamOAuth) ProcessRequest(_ http.ResponseWriter, _ *http.Request, _ interface{}) (error, int) {
	return nil, http.StatusOK
}

// EnabledForSpec will always return false for noopUpstreamOAuth.
func (d *noopUpstreamOAuth) EnabledForSpec() bool {
	if d.Spec.UpstreamAuth.OAuth.Enabled {
		d.Logger().Error("Upstream OAuth is supported only in Tyk Enterprise Edition")
	}

	return false
}

// Name returns the name of the mw.
func (d *noopUpstreamOAuth) Name() string {
	return "NooPUpstreamOAuth"
}
