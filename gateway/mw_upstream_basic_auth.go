package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
)

// UpstreamBasicAuth is a middleware that will do basic authentication for upstream connections.
// UpstreamBasicAuth middleware is only supported in Tyk OAS API definitions.
type UpstreamBasicAuth struct {
	*BaseMiddleware
}

// Name returns the name of middleware.
func (t *UpstreamBasicAuth) Name() string {
	return "UpstreamBasicAuth"
}

// EnabledForSpec returns true if the middleware is enabled based on API Spec.
func (t *UpstreamBasicAuth) EnabledForSpec() bool {
	if !t.Spec.UpstreamAuth.Enabled {
		return false
	}

	if !t.Spec.UpstreamAuth.BasicAuth.Enabled {
		return false
	}

	return true
}

// ProcessRequest will inject basic auth info into request context so that it can be used during reverse proxy.
func (t *UpstreamBasicAuth) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	basicAuthConfig := t.Spec.UpstreamAuth.BasicAuth

	authHeaderName := header.Authorization
	if basicAuthConfig.HeaderName != "" {
		authHeaderName = basicAuthConfig.HeaderName
	}
	ctx.SetUpstreamAuthHeader(r, authHeaderName)

	payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", basicAuthConfig.Username, basicAuthConfig.Password)))

	ctx.SetUpstreamAuthValue(r, payload)

	return nil, http.StatusOK
}
