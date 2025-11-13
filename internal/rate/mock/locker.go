package mock

import (
	"context"
	"sync"
)

type Locker sync.Mutex

func (m *Locker) Lock(ctx context.Context) error {
	(*sync.Mutex)(m).Lock()
	return nil
}

func (m *Locker) Unlock(ctx context.Context) error {
	(*sync.Mutex)(m).Unlock()
	return nil
}
