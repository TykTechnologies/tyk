package gateway

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
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

	upstreamBasicAuthProvider := UpstreamBasicAuthProvider{
		HeaderName: header.Authorization,
	}

	if basicAuthConfig.HeaderName != "" {
		upstreamBasicAuthProvider.HeaderName = basicAuthConfig.HeaderName
	}

	upstreamBasicAuthProvider.AuthValue = httputil.AuthHeader(basicAuthConfig.Username, basicAuthConfig.Password)

	httputil.SetUpstreamAuth(r, upstreamBasicAuthProvider)
	return nil, http.StatusOK
}

// UpstreamBasicAuthProvider implements upstream auth provider.
type UpstreamBasicAuthProvider struct {
	// HeaderName is the header name to be used to fill upstream auth with.
	HeaderName string
	// AuthValue is the value of auth header.
	AuthValue string
}

// Fill sets the request's HeaderName with AuthValue
func (u UpstreamBasicAuthProvider) Fill(r *http.Request) {
	if r.Header.Get(u.HeaderName) != "" {
		log.WithFields(logrus.Fields{
			"header": u.HeaderName,
		}).Warn(fmt.Sprintf("%s header conflict detected: client header overwritten by Gateway upstream authentication header", u.HeaderName))
	}
	r.Header.Set(u.HeaderName, u.AuthValue)
}
