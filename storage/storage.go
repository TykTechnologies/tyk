package storage

import (
	"fmt"

	"github.com/TykTechnologies/tyk/interfaces"
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

func WithKeyPrefix(prefix string) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.KeyPrefix = prefix
		}
	}
}

func WithHashKeys(hashKeys bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.HashKeys = hashKeys
		}
	}
}

func WithConnectionhandler(handler *redisCluster.ConnectionHandler) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.ConnectionHandler = handler
		}
	}
}

func NewStorageHandler(name string, opts ...func(interfaces.Handler)) (interfaces.Handler, error) {
	var impl interfaces.Handler
	switch name {
	case REDIS_CLUSTER:
		impl = &redisCluster.RedisCluster{}
	case MDCB:
		return nil, fmt.Errorf("mdcb storage handler is not implemented")
	default:
		return nil, fmt.Errorf("unknown storage handler: %s", name)
	}

	for _, opt := range opts {
		opt(impl)
	}

	return impl, nil
}
