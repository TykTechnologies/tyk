package gateway

import (
	"net/http"
)

// GlobalHeadersMiddleware implements global header modification
type GlobalHeadersMiddleware struct {
	*GlobalBaseMiddleware
	configData map[string]interface{}
}

// Name returns the middleware name
func (g *GlobalHeadersMiddleware) Name() string {
	return "GlobalHeadersMiddleware"
}

// EnabledForSpec always returns true for global middleware
func (g *GlobalHeadersMiddleware) EnabledForSpec() bool {
	return true
}

// Base returns the base middleware
func (g *GlobalHeadersMiddleware) Base() *BaseMiddleware {
	return g.GlobalBaseMiddleware.BaseMiddleware
}

// GetSpec returns the API spec
func (g *GlobalHeadersMiddleware) GetSpec() *APISpec {
	return g.GlobalBaseMiddleware.BaseMiddleware.Spec
}

// Config returns the middleware configuration
func (g *GlobalHeadersMiddleware) Config() (interface{}, error) {
	return g.configData, nil
}

// Init initializes the global headers middleware
func (g *GlobalHeadersMiddleware) Init() {
	g.GlobalBaseMiddleware.BaseMiddleware.Init()
}

// ProcessRequest processes the request and modifies headers globally
func (g *GlobalHeadersMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Add request headers
	requestHeaders := g.GetConfigMap("request_headers")
	for k, v := range requestHeaders {
		if str, ok := v.(string); ok {
			r.Header.Set(k, str)
		}
	}
	
	// Add response headers
	responseHeaders := g.GetConfigMap("response_headers")
	for k, v := range responseHeaders {
		if str, ok := v.(string); ok {
			w.Header().Set(k, str)
		}
	}
	
	// Remove request headers
	removeRequestHeaders := g.GetConfigStringSlice("remove_request_headers")
	for _, header := range removeRequestHeaders {
		r.Header.Del(header)
	}
	
	// Remove response headers (note: this affects headers going out from the gateway)
	removeResponseHeaders := g.GetConfigStringSlice("remove_response_headers")
	for _, header := range removeResponseHeaders {
		w.Header().Del(header)
	}
	
	return nil, http.StatusOK
}