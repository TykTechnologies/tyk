package upstreamoauth

import (
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	ErrorEventName = "UpstreamOAuthError"
	MiddlewareName = "UpstreamOAuth"

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

// Type Storage is a subset of storage.RedisCluster
type Storage interface {
	GetKey(key string) (string, error)
	SetKey(string, string, int64) error
	Lock(key string, timeout time.Duration) (bool, error)
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

type PasswordOAuthProvider struct{}

type TokenData struct {
	Token         string                 `json:"token"`
	ExtraMetadata map[string]interface{} `json:"extra_metadata"`
}

var (
	ctxData = httpctx.NewValue[map[string]any](ctx.ContextData)

	CtxGetData = ctxData.Get
	CtxSetData = ctxData.Set
)
