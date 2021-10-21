package storage

import (
	"context"
	"github.com/TykTechnologies/tyk/config"
	redis "github.com/go-redis/redis/v8"
	"sync/atomic"

	"time"
)

type RedisController struct {
	singlePool          atomic.Value
	singleCachePool     atomic.Value
	singleAnalyticsPool atomic.Value
	redisUp             atomic.Value
	disableRedis        atomic.Value

	ctx context.Context
}

func NewRedisController() *RedisController {
	return &RedisController{
		ctx: context.Background(),
	}
}

// DisableRedis very handy when testsing it allows to dynamically enable/disable talking with
// redisW
func (rc *RedisController) DisableRedis(ok bool) {
	if ok {
		// we make sure to set that redis is down
		rc.redisUp.Store(false)
		rc.disableRedis.Store(true)
		return
	}

	rc.disableRedis.Store(false)
	rc.WaitConnect(context.Background())
}

func (rc *RedisController) shouldConnect() bool {
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
		v := rc.singleCachePool.Load()
		if v != nil {
			return v.(redis.UniversalClient)
		}
		return nil
	}
	if analytics {
		v := rc.singleAnalyticsPool.Load()
		if v != nil {
			return v.(redis.UniversalClient)
		}
		return nil
	}
	v := rc.singlePool.Load()
	if v != nil {
		return v.(redis.UniversalClient)
	}
	return nil
}

func (rc *RedisController) connectSingleton(cache, analytics bool, conf config.Config) bool {
	d := rc.singleton(cache, analytics) == nil
	if d {
		log.Debug("Connecting to redis cluster")
		if cache {
			rc.singleCachePool.Store(NewRedisClusterPool(cache, analytics, conf))
			return true
		} else if analytics {
			rc.singleAnalyticsPool.Store(NewRedisClusterPool(cache, analytics, conf))
			return true
		}
		rc.singlePool.Store(NewRedisClusterPool(cache, analytics, conf))
		return true
	}
	return true
}

// ConnectToRedis starts a go routine that periodically tries to connect to
// redis.
//
// onConnect will be called when we have established a successful redis connection
func (rc *RedisController) ConnectToRedis(ctx context.Context, onConnect func(), conf *config.Config) {

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	c := []RedisCluster{
		{RedisController:rc},
		{IsCache: true, RedisController:rc},
		{IsAnalytics: true, RedisController:rc},
	}
	var ok bool
	for _, v := range c {
		if !rc.connectSingleton(v.IsCache, v.IsAnalytics, *conf) {
			break
		}

		if !clusterConnectionIsOpen(&v) {
			rc.redisUp.Store(false)
			break
		}
		ok = true
	}
	rc.redisUp.Store(ok)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !rc.shouldConnect() {
				continue
			}
			conn := rc.Connected()
			ok := rc.connectCluster(*conf, c...)

			rc.redisUp.Store(ok)
			if !conn && ok {
				// Here we are transitioning from DISCONNECTED to CONNECTED state
				if onConnect != nil {
					onConnect()
				}
			}
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
