package main

import (
	"net/http"
	//	"net/http/httputil"
)

// type ProxyHandler struct {
// 	TykMiddleware
// }

// type ProxyHandlerConfig struct{
// 	sH SuccessHandler
// }

// // New lets you do any initialisations for the object can be done here
// func (p *ProxyHandler) New() {
// 	tm := TykMiddleware{p.Spec, p}
// 	p.sH = SuccessHandler{p.Spec, p}
// }

// // GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
// func (p *ProxyHandler) GetConfig() (interface{}, error) {
// 	return nil, nil
// }

// // ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
// func (m *ModifiedMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
// 	p.sH.ServeHTTP(w, r)
// 	return nil,

// 	return nil, 200
// }

type DummyProxyHandler struct {
	SH SuccessHandler
}

func (d DummyProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.SH.ServeHTTP(w, r)
	return
}

// func CreateProxyHandler(p *ReverseProxy, apiSpec APISpec) func(http.Handler) http.Handler {
// 	tm := TykMiddleware{apiSpec, p}
// 	handler := SuccessHandler{tm}

// 	aliceHandler := func(h http.Handler) http.Handler {

// 		return http.HandlerFunc(handler)
// 	}

// 	return aliceHandler
// }

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
