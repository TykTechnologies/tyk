package main

import (
	"net/http"
	//	"net/http/httputil"
)

type DummyProxyHandler struct {
	SH SuccessHandler
}

func (d *DummyProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.SH.ServeHTTP(w, r)
	return
}

// DEFUNCT
// ProxyHandler Proxies requests through to their final destination, if they make it through the middleware chain.
func ProxyHandler(p *ReverseProxy, apiSpec *APISpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tm := TykMiddleware{apiSpec, p}
		handler := SuccessHandler{&tm}
		// Skip all other execution
		handler.ServeHTTP(w, r)
		return

	}
}
