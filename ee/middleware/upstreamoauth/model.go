package upstreamoauth

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	ErrorEventName                 = "UpstreamOAuthError"
	MiddlewareName                 = "UpstreamOAuth"
	ClientCredentialsAuthorizeType = "clientCredentials"
	PasswordAuthorizeType          = "password"
)

// BaseMiddleware is the subset of BaseMiddleware APIs that the middleware uses.
type BaseMiddleware interface {
	model.LoggerProvider
	FireEvent(name apidef.TykEvent, meta interface{})
}

// Gateway is the subset of Gateway APIs that the middleware uses.
type Gateway interface {
	model.ConfigProvider
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

type PasswordOAuthProvider struct{}

var (
	ctxData = httpctx.NewValue[map[string]any](ctx.ContextData)

	ctxGetData = ctxData.Get
	ctxSetData = ctxData.Set
)
