package sync

import (
	"sync"
)

// When naming a package `sync`, even if internal, it is shadowing
// the name of a stdlib package of the same name. In order to avoid
// double imports and import aliases, required stdlib apies can be
// re-exported in this internal package.
//
// This allows us to define a linter rule to suggest replacing
// usage of `sync` to `github.com/TykTechnologies/tyk/internal/sync`
// without breaking builds, and essentially extending the stdlib
// APIs within a package.

type (
	Cond      = sync.Cond
	Locker    = sync.Locker
	Map       = sync.Map
	Mutex     = sync.Mutex
	Once      = sync.Once
	Pool      = sync.Pool
	RWMutex   = sync.RWMutex
	WaitGroup = sync.WaitGroup
)
