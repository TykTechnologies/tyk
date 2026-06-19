package mock

import (
	"context"
	"sync"
)

type Locker struct {
	mu  sync.Mutex
	Err error
}

func (m *Locker) Lock(ctx context.Context) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	return nil
}

func (m *Locker) Unlock(ctx context.Context) error {
	m.mu.Unlock()
	return nil
}
