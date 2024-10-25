package middleware

import (
	"sync"

	"github.com/TykTechnologies/tyk/internal/model"
)

type ProviderFn func(model.Gateway, model.LoggerProvider, model.MergedAPI) model.Middleware

var globals = struct {
	mu       *sync.RWMutex
	registry map[string][]ProviderFn
}{
	mu:       &sync.RWMutex{},
	registry: map[string][]ProviderFn{},
}

func Add(hook string, provider ProviderFn) {
	globals.mu.Lock()
	defer globals.mu.Unlock()

	globals.registry[hook] = append(globals.registry[hook], provider)
}

func Get(hook string) []ProviderFn {
	globals.mu.RLock()
	defer globals.mu.RUnlock()

	data, _ := globals.registry[hook]
	return data
}
