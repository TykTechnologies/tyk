package newrelic

import (
	"net/http"
	"strings"

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
	router.Use(renameRelicTransactionMiddleware)
}

// renameRelicTransactionMiddleware renames transaction name with request path before any processing
func renameRelicTransactionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		txn := FromContext(ctx)
		if txn == nil {
			return
		}

		var builder strings.Builder
		builder.Grow(len(r.URL.Path) + len(r.Method) + 1)
		builder.WriteString(r.Method)
		builder.WriteString(" ")
		builder.WriteString(r.URL.Path)

		txn.SetName(builder.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
