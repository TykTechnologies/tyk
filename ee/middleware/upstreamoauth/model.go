package upstreamoauth

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	UpstreamOAuthErrorEventName    = "UpstreamOAuthError"
	UpstreamOAuthMiddlewareName    = "UpstreamOAuth"
	ClientCredentialsAuthorizeType = "clientCredentials"
	PasswordAuthorizeType          = "password"
)

// BaseMiddleware is the subset of BaseMiddleware APIs that the middleware uses.
type BaseMiddleware interface {
	model.LoggerProvider
}

// Gateway is the subset of Gateway APIs that the middleware uses.
type Gateway interface {
	model.ConfigProvider
	model.UpstreamOAuthCacheProvider
}

// APISpec is a subset of gateway.APISpec for the values the middleware consumes.
type APISpec struct {
	APIID string
	Name  string
	IsOAS bool
	OAS   oas.OAS

	UpstreamAuth apidef.UpstreamAuth
}

// NewAPISpec creates a new APISpec object based on the required inputs.
// The resulting object is a subset of `*gateway.APISpec`.
func NewAPISpec(id string, name string, isOasDef bool, oasDef oas.OAS, upstreamAuth apidef.UpstreamAuth) *APISpec {
	return &APISpec{
		APIID:        id,
		Name:         name,
		IsOAS:        isOasDef,
		OAS:          oasDef,
		UpstreamAuth: upstreamAuth,
	}
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

type PasswordOAuthProvider struct{}
