package errcoll

import "sync"

func New() *Coll {
	return &Coll{}
}

type Coll struct {
	mu  sync.RWMutex
	err error
}

func (c *Coll) Push(fn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err != nil {
		return
	}

	c.err = fn()
}

func (c *Coll) Err() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.err
}
