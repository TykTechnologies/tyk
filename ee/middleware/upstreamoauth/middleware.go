package upstreamoauth

import (
	"fmt"
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
	return "UpstreamOAuthMiddleware"
}

// EnabledForSpec checks if streaming is enabled on the config.
func (m *Middleware) EnabledForSpec() bool {
	if !m.Spec.UpstreamAuth.IsEnabled() {
		return false
	}

	if !m.Spec.UpstreamAuth.OAuth.Enabled {
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
	oauthConfig := m.Spec.UpstreamAuth.OAuth

	upstreamOAuthProvider := Provider{
		HeaderName: header.Authorization,
	}

	provider, err := getOAuthHeaderProvider(oauthConfig)
	if err != nil {
		return fmt.Errorf("failed to get OAuth header provider: %w", err), http.StatusInternalServerError
	}

	payload, err := provider.getOAuthToken(r, m)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err), http.StatusInternalServerError
	}

	upstreamOAuthProvider.AuthValue = payload
	headerName := provider.getHeaderName(m)
	if headerName != "" {
		upstreamOAuthProvider.HeaderName = headerName
	}

	if provider.headerEnabled(m) {
		headerName := provider.getHeaderName(m)
		if headerName != "" {
			upstreamOAuthProvider.HeaderName = headerName
		}
	}

	httputil.SetUpstreamAuth(r, upstreamOAuthProvider)
	return nil, http.StatusOK
}
