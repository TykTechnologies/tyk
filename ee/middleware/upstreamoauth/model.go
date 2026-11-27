package upstreamoauth

import (
	"crypto/tls"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpclient"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	MiddlewareName = "UpstreamOAuth"

	ClientCredentialsAuthorizeType = "clientCredentials"
	PasswordAuthorizeType          = "password"
	JWTBearerAuthorizeType         = "jwtBearer"
)

// BaseMiddleware is the subset of BaseMiddleware APIs that the middleware uses.
type BaseMiddleware interface {
	model.LoggerProvider
	FireEvent(name apidef.TykEvent, meta interface{})
	// GetClientCertificate returns the certificate (with private key) stored
	// under certID in the gateway certificate store.
	GetClientCertificate(certID string) (*tls.Certificate, error)
}

// Gateway is the subset of Gateway APIs that the middleware uses.
type Gateway interface {
	model.ConfigProvider
	GetCertificateManager() httpclient.CertificateManager
}

// Type Storage is a subset of storage.RedisCluster
type Storage interface {
	GetKey(key string) (string, error)
	SetKey(string, string, int64) error
	Lock(key string, timeout time.Duration) (bool, error)
	// DeleteRawKey removes a key without applying the storage prefix. It releases
	// the token lock, which Lock also stores unprefixed.
	DeleteRawKey(key string) bool
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
