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

func (d *noopUpstreamBasicAuth) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	return nil, http.StatusOK
}

func (d *noopUpstreamBasicAuth) EnabledForSpec() bool {
	if d.Spec.UpstreamAuth.BasicAuth.Enabled {
		d.Logger().Error("Upstream basic auth is supported only in Tyk Enterprise Edition")
	}

	return false
}

func (d *noopUpstreamBasicAuth) Name() string {
	return "NooPUpstreamBasicAuth"
}
