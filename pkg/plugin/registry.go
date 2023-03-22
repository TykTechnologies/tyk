package plugin

import (
	"net/http"
	"sync"
)

var (
	initializer sync.Once
	mu          sync.RWMutex

	requestHandlers map[string]http.HandlerFunc
)

func init() {
	initializer.Do(func() {
		requestHandlers = make(map[string]http.HandlerFunc)
	})
}

func key(namespace string, symbol string) string {
	return namespace + "/" + symbol
}

func registerHandler(namespace string, symbol string, handler http.HandlerFunc) {
	mu.Lock()
	defer mu.Unlock()

	requestHandlers[key(namespace, symbol)] = handler
}

func handler(namespace string, symbol string) http.HandlerFunc {
	mu.Lock()
	defer mu.Unlock()

	return requestHandlers[key(namespace, symbol)]
}
