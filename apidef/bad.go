package apidef

import "sync"

type TestChange struct {
	sync.Mutex
}

func (p TestChange) Copy() TestChange {
	return p
}
