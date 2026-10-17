package kafka

import (
	"context"
	"errors"
	"sync"
)

// RuntimeAckKeyRegistry transfers cluster-consistent, scope-derived signing
// configuration from the Gateway into Bento-created input instances without
// serializing secrets into stream YAML.
type RuntimeAckKeyRegistry struct {
	mu        sync.RWMutex
	resolvers map[string]runtimeAckKeyEntry
	nextOwner uint64
}

type runtimeAckKeyEntry struct {
	resolver AckTokenCodecResolver
	owner    uint64
}

type RuntimeAckKeyRegistration struct {
	registry    *RuntimeAckKeyRegistry
	componentID string
	owner       uint64
}

func NewRuntimeAckKeyRegistry() *RuntimeAckKeyRegistry {
	return &RuntimeAckKeyRegistry{resolvers: make(map[string]runtimeAckKeyEntry)}
}

func (r *RuntimeAckKeyRegistry) Configure(componentID string, resolver AckTokenCodecResolver) error {
	return r.ConfigureWithInvalidation(componentID, resolver, false)
}
func (r *RuntimeAckKeyRegistry) ConfigureWithInvalidation(componentID string, resolver AckTokenCodecResolver, force bool) error {
	_, err := r.ConfigureRegistrationWithInvalidation(componentID, resolver, force)
	return err
}

func (r *RuntimeAckKeyRegistry) ConfigureRegistrationWithInvalidation(componentID string, resolver AckTokenCodecResolver, force bool) (*RuntimeAckKeyRegistration, error) {
	if r == nil || componentID == "" || resolver == nil {
		return nil, errors.New("component ID and acknowledgment key resolver are required")
	}
	r.mu.Lock()
	if current, ok := r.resolvers[componentID].resolver.(*SharedAckSigningKeyProvider); ok {
		if next, ok := resolver.(*SharedAckSigningKeyProvider); ok {
			active, secrets := next.snapshot()
			var err error
			if force {
				err = current.ForceRotate(active, secrets)
			} else {
				err = current.Rotate(active, secrets)
			}
			if err != nil {
				r.mu.Unlock()
				return nil, err
			}
			resolver = current
		}
	}
	r.nextOwner++
	if r.nextOwner == 0 {
		r.nextOwner++
	}
	owner := r.nextOwner
	r.resolvers[componentID] = runtimeAckKeyEntry{resolver: resolver, owner: owner}
	r.mu.Unlock()
	return &RuntimeAckKeyRegistration{registry: r, componentID: componentID, owner: owner}, nil
}

func (r *RuntimeAckKeyRegistry) Resolve(ctx context.Context, componentID, scope string) (*AckTokenCodec, error) {
	if r == nil {
		return nil, errors.New("acknowledgment key registry unavailable")
	}
	r.mu.RLock()
	resolver := r.resolvers[componentID].resolver
	r.mu.RUnlock()
	if resolver == nil {
		return nil, errors.New("acknowledgment signing keys are not configured")
	}
	return resolver.ResolveAckTokenCodec(ctx, scope)
}

func (r *RuntimeAckKeyRegistration) Remove() bool {
	if r == nil || r.registry == nil {
		return false
	}
	r.registry.mu.Lock()
	defer r.registry.mu.Unlock()
	entry, ok := r.registry.resolvers[r.componentID]
	if !ok || entry.owner != r.owner {
		return false
	}
	delete(r.registry.resolvers, r.componentID)
	return true
}

func (r *RuntimeAckKeyRegistry) Remove(componentID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.resolvers, componentID)
	r.mu.Unlock()
}

var GlobalRuntimeAckKeyRegistry = NewRuntimeAckKeyRegistry()
