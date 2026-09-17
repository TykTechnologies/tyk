package kafka

import (
	"context"
	"errors"
	"sync"
)

// ResetStateStoreProvider lets Streams inject a store backed by the Gateway's
// existing Redis lifecycle rather than opening a connector-owned connection.
type ResetStateStoreProvider interface {
	ResolveResetStateStore(context.Context, string) (ResetStateStore, error)
}

type StaticResetStateStoreProvider struct{ Store ResetStateStore }

func (p StaticResetStateStoreProvider) ResolveResetStateStore(context.Context, string) (ResetStateStore, error) {
	if p.Store == nil {
		return nil, errors.New("reset state store unavailable")
	}
	return p.Store, nil
}

type runtimeResetStoreEntry struct {
	provider ResetStateStoreProvider
	owner    uint64
}

type RuntimeResetStateStoreRegistry struct {
	mu        sync.RWMutex
	providers map[string]runtimeResetStoreEntry
	nextOwner uint64
}

type RuntimeResetStateStoreRegistration struct {
	registry    *RuntimeResetStateStoreRegistry
	componentID string
	owner       uint64
}

func NewRuntimeResetStateStoreRegistry() *RuntimeResetStateStoreRegistry {
	return &RuntimeResetStateStoreRegistry{providers: make(map[string]runtimeResetStoreEntry)}
}

func (r *RuntimeResetStateStoreRegistry) Configure(componentID string, provider ResetStateStoreProvider) (*RuntimeResetStateStoreRegistration, error) {
	if r == nil || componentID == "" || provider == nil {
		return nil, errors.New("component ID and reset state store provider are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[componentID]; exists {
		return nil, errors.New("reset state store already configured")
	}
	r.nextOwner++
	if r.nextOwner == 0 {
		r.nextOwner++
	}
	r.providers[componentID] = runtimeResetStoreEntry{provider: provider, owner: r.nextOwner}
	return &RuntimeResetStateStoreRegistration{registry: r, componentID: componentID, owner: r.nextOwner}, nil
}

func (r *RuntimeResetStateStoreRegistry) Resolve(ctx context.Context, componentID string) (ResetStateStore, error) {
	if r == nil {
		return nil, errors.New("reset state store registry unavailable")
	}
	r.mu.RLock()
	entry, ok := r.providers[componentID]
	r.mu.RUnlock()
	if !ok {
		return nil, errors.New("reset state store is not configured")
	}
	return entry.provider.ResolveResetStateStore(ctx, componentID)
}

func (r *RuntimeResetStateStoreRegistration) Remove() bool {
	if r == nil || r.registry == nil {
		return false
	}
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	entry, ok := r.registry.providers[r.componentID]
	if !ok || entry.owner != r.owner {
		return false
	}
	delete(r.registry.providers, r.componentID)
	return true
}

var GlobalRuntimeResetStateStoreRegistry = NewRuntimeResetStateStoreRegistry()
