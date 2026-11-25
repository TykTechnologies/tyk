package kafka

import (
	"context"
	"errors"
	"sync"
)

type DurableAckTransportProvider interface {
	ResolveDurableAckTransport(context.Context, string) (DurableAckTransport, error)
}

type StaticDurableAckTransportProvider struct{ Transport DurableAckTransport }

func (p StaticDurableAckTransportProvider) ResolveDurableAckTransport(context.Context, string) (DurableAckTransport, error) {
	if p.Transport == nil {
		return nil, errors.New("durable acknowledgment transport unavailable")
	}
	return p.Transport, nil
}

type runtimeTransportEntry struct {
	provider DurableAckTransportProvider
	owner    uint64
}

type RuntimeAckTransportRegistry struct {
	mu        sync.RWMutex
	providers map[string]runtimeTransportEntry
	nextOwner uint64
}

type RuntimeAckTransportRegistration struct {
	registry    *RuntimeAckTransportRegistry
	componentID string
	owner       uint64
}

func NewRuntimeAckTransportRegistry() *RuntimeAckTransportRegistry {
	return &RuntimeAckTransportRegistry{providers: make(map[string]runtimeTransportEntry)}
}

func (r *RuntimeAckTransportRegistry) Configure(componentID string, provider DurableAckTransportProvider) (*RuntimeAckTransportRegistration, error) {
	if r == nil || componentID == "" || provider == nil {
		return nil, errors.New("component ID and durable acknowledgment transport provider are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[componentID]; exists {
		return nil, errors.New("durable acknowledgment transport already configured")
	}
	r.nextOwner++
	if r.nextOwner == 0 {
		r.nextOwner++
	}
	r.providers[componentID] = runtimeTransportEntry{provider: provider, owner: r.nextOwner}
	return &RuntimeAckTransportRegistration{registry: r, componentID: componentID, owner: r.nextOwner}, nil
}

func (r *RuntimeAckTransportRegistry) Resolve(ctx context.Context, componentID string) (DurableAckTransport, error) {
	if r == nil {
		return nil, errors.New("durable acknowledgment transport registry unavailable")
	}
	r.mu.RLock()
	entry, ok := r.providers[componentID]
	r.mu.RUnlock()
	if !ok {
		return nil, errors.New("durable acknowledgment transport is not configured")
	}
	return entry.provider.ResolveDurableAckTransport(ctx, componentID)
}

func (r *RuntimeAckTransportRegistration) Remove() bool {
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

var GlobalRuntimeAckTransportRegistry = NewRuntimeAckTransportRegistry()
