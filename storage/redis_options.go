package storage

import (
	"github.com/TykTechnologies/tyk/interfaces"
	redisCluster "github.com/TykTechnologies/tyk/storage/redis-cluster"
)

// Redis Cluster Options
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

func WithConnectionHandler(handler *redisCluster.ConnectionHandler) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.ConnectionHandler = handler
		}
	}
}

func IsCache(cache bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.IsCache = cache
		}
	}
}

func IsAnalytics(analytics bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.IsAnalytics = analytics
		}
	}
}

func WithRedisController(controller *redisCluster.RedisController) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*redisCluster.RedisCluster); ok {
			impl.RedisController = controller
		}
	}
}
