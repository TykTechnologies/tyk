package plugin

import (
	"net/http"
)

// RegisterHandler registers a handler for a name/symbol pair.
func RegisterHandler(namespace string, symbol string, handler http.HandlerFunc) {
	registerHandler(namespace, symbol, handler)
}

// Handler returns a registered handler for a name/symbol pair. The function
// will return nil in case no such handler is registered.
func Handler(namespace string, symbol string) http.HandlerFunc {
	return handler(namespace, symbol)
}
