package upstreambasicauth

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Middleware implements upstream basic auth middleware.
type Middleware struct {
	Spec *APISpec
	Gw   Gateway

	base BaseMiddleware
}

// Middleware implements model.Middleware.
var _ model.Middleware = &Middleware{}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw Gateway, mw BaseMiddleware, spec *APISpec) *Middleware {
	return &Middleware{
		base: mw,
		Gw:   gw,
		Spec: spec,
	}
}

// Logger returns a logger with middleware filled out.
func (m *Middleware) Logger() *logrus.Entry {
	return m.base.Logger().WithField("mw", m.Name())
}

// Name returns the name for the middleware.
func (m *Middleware) Name() string {
	return "UpstreamBasicAuthMiddleware"
}

// EnabledForSpec checks if streaming is enabled on the config.
func (m *Middleware) EnabledForSpec() bool {
	if !m.Spec.UpstreamAuth.IsEnabled() {
		return false
	}

	if !m.Spec.UpstreamAuth.BasicAuth.Enabled {
		return false
	}

	return true
}

// Init initializes the middleware.
func (m *Middleware) Init() {
	m.Logger().Debug("Initializing Upstream basic auth Middleware")
}

// ProcessRequest will handle upstream basic auth.
func (m *Middleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	basicAuthConfig := m.Spec.UpstreamAuth.BasicAuth

	upstreamBasicAuthProvider := Provider{
		Logger:     m.Logger(),
		HeaderName: header.Authorization,
	}

	if basicAuthConfig.Header.AuthKeyName() != "" {
		upstreamBasicAuthProvider.HeaderName = basicAuthConfig.Header.AuthKeyName()
	}

	upstreamBasicAuthProvider.AuthValue = httputil.AuthHeader(basicAuthConfig.Username, basicAuthConfig.Password)

	httputil.SetUpstreamAuth(r, upstreamBasicAuthProvider)
	return nil, http.StatusOK
}
