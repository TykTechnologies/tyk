//go:build ee || dev

// Package oauth2tokenexchange is the EE runtime for RFC 8693 token exchange.
// It reads oauth2common.State set by the OSS OAuth2Middleware and replaces
// the Authorization header with the exchanged token on success.
package oauth2tokenexchange

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

type Middleware struct {
	Spec model.MergedAPI
	Base BaseMiddleware
}

func NewMiddleware(base BaseMiddleware, spec model.MergedAPI) *Middleware {
	return &Middleware{Base: base, Spec: spec}
}

func (m *Middleware) Logger() *logrus.Entry {
	return m.Base.Logger().WithField("mw", m.Name())
}

func (m *Middleware) Name() string {
	return MiddlewareName
}

// Init is required by model.Middleware.
func (m *Middleware) Init() {}

// Unload is required by model.Middleware.
func (m *Middleware) Unload() {}

// EnabledForSpec reports whether the EE exchange runtime should run for this spec.
func (m *Middleware) EnabledForSpec() bool {
	cfg := m.lookupOAuth2Config()
	if cfg == nil {
		return false
	}
	return cfg.TokenExchange != nil && cfg.TokenExchange.Enabled
}

// lookupOAuth2Config returns the first oauth2 scheme config in the OAS Tyk extension.
func (m *Middleware) lookupOAuth2Config() *oas.OAuth2 {
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil {
		return nil
	}
	if ext.Server.Authentication == nil {
		return nil
	}
	for name := range ext.Server.Authentication.SecuritySchemes {
		if cfg := m.Spec.OAS.GetTykOAuth2Config(name); cfg != nil {
			return cfg
		}
	}
	return nil
}

var errExchangeRendered = fmt.Errorf("%w: oauth2 exchange", middleware.ErrResponseRendered)

// ProcessRequest runs the RFC 8693 exchange; no-ops when no State is set or exchange is disabled.
func (m *Middleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if oauth2common.IsExchangeDone(r) {
		return nil, http.StatusOK
	}

	st := oauth2common.GetState(r)
	if st == nil || st.OASConfig == nil {
		return nil, http.StatusOK
	}
	if st.OASConfig.TokenExchange == nil || !st.OASConfig.TokenExchange.Enabled {
		return nil, http.StatusOK
	}

	_, err := m.runExchange(r, st)
	if err != nil {
		switch e := err.(type) {
		case *oauth2common.NoMatchingProviderError:
			m.writeNoMatchingProviderResponse(w, r, e)
		case *oauth2common.MisconfigError:
			m.writeMisconfigResponse(w, r, e)
		default:
			m.writeExchangeFailedResponse(w, r, err)
		}
		return errExchangeRendered, middleware.StatusRespond
	}

	oauth2common.MarkExchangeDone(r)
	return nil, http.StatusOK
}
