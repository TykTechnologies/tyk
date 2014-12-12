package main

import (
	"net/http"
	//	"net/http/httputil"
)

// ProxyHandler Proxies requests through to their final destination, if they make it through the middleware chain.
func ProxyHandler(p *ReverseProxy, apiSpec APISpec) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tm := TykMiddleware{apiSpec, p}
		handler := SuccessHandler{tm}
		// Skip all other execution
		handler.ServeHTTP(w, r)
		return

	}
}
