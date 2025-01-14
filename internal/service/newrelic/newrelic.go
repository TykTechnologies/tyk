package newrelic

import (
	"github.com/gorilla/mux"
	"github.com/newrelic/go-agent/v3/integrations/nrgorilla"
	"github.com/newrelic/go-agent/v3/newrelic"
)

// Type aliases used from newrelic pkg.
type (
	Application  = newrelic.Application
	Transaction  = newrelic.Transaction
	ConfigOption = newrelic.ConfigOption
)

// Variable aliases used from newrelic pkg.
var (
	NewApplication = newrelic.NewApplication
	FromContext    = newrelic.FromContext

	ConfigLogger                   = newrelic.ConfigLogger
	ConfigEnabled                  = newrelic.ConfigEnabled
	ConfigAppName                  = newrelic.ConfigAppName
	ConfigLicense                  = newrelic.ConfigLicense
	ConfigDistributedTracerEnabled = newrelic.ConfigDistributedTracerEnabled
)

// Mount adds the nrgorilla middleware to the router. The application is added to the request context.
// If app is nil, nothing will be done and the function will return.
func Mount(router *mux.Router, app *Application) {
	if app == nil {
		return
	}

	router.Use(nrgorilla.Middleware(app))
}
