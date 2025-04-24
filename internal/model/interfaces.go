package model

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

// Gateway is a collection of well defined gateway interfaces. It should only
// be implemented in full by gateway.Gateway, and is used for a built-time
// type assertion. Do not use the symbol elsewhere, use the smaller interfaces.
type Gateway interface {
	ConfigProvider
	PolicyProvider

	ReplaceTykVariables
}

// Middleware is a subset of the gateway.Middleware interface, that can be
// implemented outside of gateway scope.
type Middleware interface {
	Init()
	Name() string
	Logger() *logrus.Entry
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
	Unload()
}

// LoggerProvider returns a new *logrus.Entry for the request.
// It's implemented by gateway and middleware. Middleware typically
// adds the `mw` field with the middleware name.
type LoggerProvider interface {
	Logger() *logrus.Entry
}

// ConfigProvider provides a typical config getter signature.
type ConfigProvider interface {
	GetConfig() config.Config
}

// PolicyProvider is a storage interface encapsulating policy retrieval.
type PolicyProvider interface {
	PolicyCount() int
	PolicyIDs() []string
	PolicyByID(string) (user.Policy, bool)
}

// These are utility methods without any real data model design around them.
type (
	// ReplaceTykVariables is a request-based template replacement hook.
	// Implemented by gateway.Gateway.
	ReplaceTykVariables interface {
		ReplaceTykVariables(r *http.Request, in string, escape bool) string
	}

	// StripListenPath is the interface implemented by APISpec.StripListenPath.
	StripListenPath interface {
		StripListenPath(string) string
	}

	// StripListenPathFunc is the function signature for StripListenPath.
	StripListenPathFunc func(string) string
)
