// Package storage re-exports the parts of the gateway storage package that a
// host of the control-plane library (for example the Dashboard in embedded
// mode) needs to open the shared Redis and build the stores the library
// operates on. Hosts import this package instead of the gateway's internal
// storage package.
package storage

import "github.com/TykTechnologies/tyk/storage"

type (
	// ConnectionHandler owns the Redis connections of one library host.
	ConnectionHandler = storage.ConnectionHandler
	// Handler is the key/value store interface the library writes through.
	Handler = storage.Handler
	// RedisCluster is the Redis-backed Handler, keyed by prefix.
	RedisCluster = storage.RedisCluster
)

const (
	// HashMurmur64 is the default key hash function name.
	HashMurmur64 = storage.HashMurmur64
)

var (
	// NewConnectionHandler creates a ConnectionHandler bound to ctx.
	NewConnectionHandler = storage.NewConnectionHandler
	// HashKey hashes a key name when hashing is enabled.
	HashKey = storage.HashKey
	// HashStr hashes with the configured hash function.
	HashStr = storage.HashStr
)
