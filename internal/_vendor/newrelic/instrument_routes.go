// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nrgorilla instruments https://github.com/gorilla/mux applications.
//
// Use this package to instrument inbound requests handled by a gorilla
// mux.Router.  Call nrgorilla.InstrumentRoutes on your gorilla mux.Router
// after your routes have been added to it.
//
// Example: https://github.com/newrelic/go-agent/tree/master/_integrations/nrgorilla/v1/example/main.go
package newrelic

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/_vendor/mux"

	agent "github.com/newrelic/go-agent"
)

type instrumentedHandler struct {
	name string
	app  agent.Application
	orig http.Handler
}

func (h instrumentedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	txn := h.app.StartTransaction(h.name, w, r)
	defer txn.End()

	r = agent.RequestWithTransactionContext(r, txn)

	h.orig.ServeHTTP(txn, r)
}

func instrumentRoute(h http.Handler, app agent.Application, name string) http.Handler {
	if _, ok := h.(instrumentedHandler); ok {
		return h
	}
	return instrumentedHandler{
		name: name,
		orig: h,
		app:  app,
	}
}

func routeName(route *mux.Route) string {
	if nil == route {
		return ""
	}
	if n := route.GetName(); n != "" {
		return n
	}
	if n, _ := route.GetPathTemplate(); n != "" {
		return n
	}
	n, _ := route.GetHostTemplate()
	return n
}

// InstrumentRoutes instruments requests through the provided mux.Router.  Use
// this after the routes have been added to the router.
func InstrumentRoutes(r *mux.Router, app agent.Application) *mux.Router {
	if app != nil {
		r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			h := instrumentRoute(route.GetHandler(), app, routeName(route))
			route.Handler(h)
			return nil
		})
		if nil != r.NotFoundHandler {
			r.NotFoundHandler = instrumentRoute(r.NotFoundHandler, app, "NotFoundHandler")
		}
	}
	return r
}
