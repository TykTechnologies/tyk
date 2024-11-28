package upstreamoauth

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Middleware implements upstream OAuth middleware.
type Middleware struct {
	Spec model.MergedAPI
	Gw   Gateway

	Base BaseMiddleware

	clientCredentialsStorageHandler Storage
	passwordStorageHandler          Storage
}

// Middleware implements model.Middleware.
var _ model.Middleware = &Middleware{}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw Gateway, mw BaseMiddleware, spec model.MergedAPI, ccStorageHandler Storage, pwStorageHandler Storage) *Middleware {
	return &Middleware{
		Base:                            mw,
		Gw:                              gw,
		Spec:                            spec,
		clientCredentialsStorageHandler: ccStorageHandler,
		passwordStorageHandler:          pwStorageHandler,
	}
}

// Logger returns a logger with middleware filled out.
func (m *Middleware) Logger() *logrus.Entry {
	return m.Base.Logger().WithField("mw", m.Name())
}

// Name returns the name for the middleware.
func (m *Middleware) Name() string {
	return MiddlewareName
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

// ProcessRequest will handle upstream OAuth.
func (m *Middleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	provider, err := NewOAuthHeaderProvider(m.Spec.UpstreamAuth.OAuth)
	if err != nil {
		return fmt.Errorf("failed to get OAuth header provider: %w", err), http.StatusInternalServerError
	}

	payload, err := provider.getOAuthToken(r, m)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err), http.StatusInternalServerError
	}

	upstreamOAuthProvider := Provider{
		HeaderName: header.Authorization,
		AuthValue:  payload,
		Logger:     m.Logger(),
	}

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

// FireEvent emits an upstream OAuth event with an optional custom message.
func (mw *Middleware) FireEvent(r *http.Request, e event.Event, message string, apiId string) {
	if message == "" {
		message = event.String(e)
	}
	mw.Base.FireEvent(e, EventUpstreamOAuthMeta{
		EventMetaDefault: model.NewEventMetaDefault(r, message),
		APIID:            apiId,
	})
}
