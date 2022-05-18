package storage

import (
	"context"
	"sync/atomic"
	"time"

	redis "github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/config"
)

type RedisController struct {
	singlePool          redis.UniversalClient
	singleCachePool     redis.UniversalClient
	singleAnalyticsPool redis.UniversalClient

	redisUp      atomic.Value
	disableRedis atomic.Value

	ctx       context.Context
	reconnect chan struct{}
}

func NewRedisController(ctx context.Context) *RedisController {
	return &RedisController{
		ctx:       ctx,
		reconnect: make(chan struct{}, 1),
	}
}

// DisableRedis allows to dynamically enable/disable talking with redisW
func (rc *RedisController) DisableRedis(setRedisDown bool) {
	if setRedisDown {
		// we make sure x set that redis is down
		rc.disableRedis.Store(true)
		rc.redisUp.Store(false)
		return
	}

	rc.disableRedis.Store(false)
	rc.redisUp.Store(false)

	rc.reconnect <- struct{}{}

	ctx, cancel := context.WithTimeout(rc.ctx, 5*time.Second)
	defer cancel()

	if !rc.WaitConnect(ctx) {
		panic("Can't reconnect to redis after disable")
	}
}

func (rc *RedisController) enabled() bool {
	ok := true
	if v := rc.disableRedis.Load(); v != nil {
		ok = !v.(bool)
	}
	return ok
}

// Connected returns true if we are connected to redis
func (rc *RedisController) Connected() bool {
	v := rc.redisUp.Load()
	if v != nil {
		return v.(bool)
	}
	return false
}

func (rc *RedisController) WaitConnect(ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			if rc.Connected() {
				return true
			}

			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (rc *RedisController) singleton(cache, analytics bool) redis.UniversalClient {
	if cache {
		return rc.singleCachePool
	}
	if analytics {
		return rc.singleAnalyticsPool
	}
	return rc.singlePool
}

func (rc *RedisController) connectSingleton(cache, analytics bool, conf config.Config) bool {
	if conn := rc.singleton(cache, analytics); conn != nil {
		return true
	}

	if cache {
		rc.singleCachePool = NewRedisClusterPool(cache, analytics, conf)
		return true
	}

	if analytics {
		rc.singleAnalyticsPool = NewRedisClusterPool(cache, analytics, conf)
		return true
	}
	rc.singlePool = NewRedisClusterPool(cache, analytics, conf)
	return true
}

// disconnect all redis clients created
func (rc *RedisController) disconnect() {
	for _, v := range []redis.UniversalClient{
		rc.singleCachePool,
		rc.singleAnalyticsPool,
		rc.singlePool,
	} {
		defer v.Close()
	}
}

// ConnectToRedis starts a go routine that periodically tries to connect to
// redis.
//
// onConnect will be called when we have established a successful redis connection
func (rc *RedisController) ConnectToRedis(ctx context.Context, onConnect func(), conf *config.Config) {
	if onConnect == nil {
		onConnect = func() {
			// an empty function to avoid repeated nil checks below
		}
	}
	c := []RedisCluster{
		{
			RedisController: rc,
		},
		{
			IsCache:         true,
			RedisController: rc,
		},
		{
			IsAnalytics:     true,
			RedisController: rc,
		},
	}

	up := true
	for _, v := range c {
		if !rc.connectSingleton(v.IsCache, v.IsAnalytics, *conf) {
			up = false
			break
		}

		if !clusterConnectionIsOpen(&v) {
			up = false
			break
		}
	}

	rc.redisUp.Store(up)
	if up {
		onConnect()
	}

	defer func() {
		close(rc.reconnect)
		rc.disconnect()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.reconnect:
			break
		}

		if !rc.enabled() {
			continue
		}

		ok := rc.connectCluster(*conf, c...)

		rc.redisUp.Store(ok)

		if ok {
			onConnect()
		}
	}
}

func (rc *RedisController) connectCluster(conf config.Config, v ...RedisCluster) bool {
	for _, x := range v {
		if ok := rc.establishConnection(&x, conf); ok {
			return ok
		}
	}
	return false
}

func (rc *RedisController) establishConnection(v *RedisCluster, conf config.Config) bool {
	if !rc.connectSingleton(v.IsCache, v.IsAnalytics, conf) {
		return false
	}
	return clusterConnectionIsOpen(v)
}
