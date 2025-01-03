package newrelic

import (
	"github.com/newrelic/go-agent/v3/integrations/nrgorilla"
	"github.com/newrelic/go-agent/v3/newrelic"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/httpctx"
)

type (
	Application  = newrelic.Application
	Transaction  = newrelic.Transaction
	ConfigOption = newrelic.ConfigOption
)

var (
	NewApplication = newrelic.NewApplication

	// Context exposes a repository for the newrelic *Transaction.
	Context = httpctx.NewValue[*Transaction]("internal:new-relic-transaction")

	ConfigLogger                   = newrelic.ConfigLogger
	ConfigEnabled                  = newrelic.ConfigEnabled
	ConfigAppName                  = newrelic.ConfigAppName
	ConfigLicense                  = newrelic.ConfigLicense
	ConfigDistributedTracerEnabled = newrelic.ConfigDistributedTracerEnabled
)

// AddNewRelicInstrumentation adds NewRelic instrumentation to the router
func AddNewRelicInstrumentation(app *newrelic.Application, r *mux.Router) {
	r.Use(nrgorilla.Middleware(app))
}
