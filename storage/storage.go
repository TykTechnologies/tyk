package storage

import (
	"fmt"

	"github.com/TykTechnologies/tyk/interfaces"
	"github.com/TykTechnologies/tyk/storage/mdcb"
	redisCluster "github.com/TykTechnologies/tyk/storage/redis-cluster"
)

const (
	REDIS_CLUSTER = "redis"
	MDCB          = "mdcb"
	DUMMY         = "dummy"
)

type AnalyticsHandler interface {
	Connect() bool
	AppendToSetPipelined(string, [][]byte)
	GetAndDeleteSet(string) []interface{}
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
}

func NewStorageHandler(name string, opts ...func(interfaces.Handler)) (interfaces.Handler, error) {
	var impl interfaces.Handler
	switch name {
	case REDIS_CLUSTER:
		impl = &redisCluster.RedisCluster{}
	case MDCB:
		impl = mdcb.MdcbStorage{}

	default:
		return nil, fmt.Errorf("unknown storage handler: %s", name)
	}

	for _, opt := range opts {
		opt(impl)
	}

	return impl, nil
}

const (
	DEFAULT_MODULE = "default"
)

// GetStorageForModule returns the storage type for the given module.
// Defaults to REDIS_CLUSTER for the initial implementation.
func GetStorageForModule(module string) string {
	return REDIS_CLUSTER
}
