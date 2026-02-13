package newrelic

import (
	"context"
	"net/http"

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

// Context key - contains request path before any processing
type requestPathKey struct{}

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
	router.Use(storeOriginalPathMiddleware)
}

// storeOriginalPathMiddleware stores the original full request path before any processing
func storeOriginalPathMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestPathKey{}, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RenameTransaction renames the New Relic transaction to include the full request path
func RenameTransaction(r *http.Request) {
	ctx := r.Context()
	txn := FromContext(ctx)
	if txn == nil {
		return
	}

	originalPath, ok := ctx.Value(requestPathKey{}).(string)
	if !ok {
		return
	}

	txn.SetName(r.Method + " " + originalPath)
}
