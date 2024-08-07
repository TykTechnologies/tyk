package redisCluster

import "github.com/TykTechnologies/tyk/interfaces"

// Redis Cluster Options
func WithKeyPrefix(prefix string) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.KeyPrefix = prefix
		}
	}
}

func WithHashKeys(hashKeys bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.HashKeys = hashKeys
		}
	}
}

func WithConnectionhandler(handler *ConnectionHandler) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.ConnectionHandler = handler
		}
	}
}

func IsCache(cache bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.IsCache = cache
		}
	}
}

func IsAnalytics(analytics bool) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.IsAnalytics = analytics
		}
	}
}

func WithRedisController(controller *RedisController) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*RedisCluster); ok {
			impl.RedisController = controller
		}
	}
}
