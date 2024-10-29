package upstreamoauth

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
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

// APISpec is a subset of gateway.APISpec for the values the middleware consumes.
type APISpec struct {
	APIID string
	Name  string
	IsOAS bool
	OAS   oas.OAS

	UpstreamAuth apidef.UpstreamAuth
}

type ClientCredentialsOAuthProvider struct{}

type PerAPIClientCredentialsOAuthProvider struct{}

type PasswordOAuthProvider struct{}
