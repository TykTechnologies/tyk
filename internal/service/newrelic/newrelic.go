package newrelic

import (
	"github.com/newrelic/go-agent/v3/integrations/nrgorilla"
	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/httpctx"
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

	ConfigLogger                   = newrelic.ConfigLogger
	ConfigEnabled                  = newrelic.ConfigEnabled
	ConfigAppName                  = newrelic.ConfigAppName
	ConfigLicense                  = newrelic.ConfigLicense
	ConfigDistributedTracerEnabled = newrelic.ConfigDistributedTracerEnabled
)

var (
	// Context exposes a repository for the newrelic *Transaction on request context.
	Context = httpctx.NewValue[*Transaction]("internal:new-relic-transaction")
)

// AddNewRelicInstrumentation adds NewRelic instrumentation to the router.
func AddNewRelicInstrumentation(app *newrelic.Application, r *mux.Router) {
	r.Use(nrgorilla.Middleware(app))
}
