package storage

import (
	"context"
	"sync/atomic"

<<<<<<< HEAD
	"github.com/TykTechnologies/tyk/config"
=======
	"github.com/cenk/backoff"
>>>>>>> ccecd4cd... [TT-8901] Preventing panics if cache_storage is down (#5065)
	redis "github.com/go-redis/redis/v8"

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
func (rc *RedisController) DisableRedis(setRedisDown bool) {
	if setRedisDown {
		// we make sure x set that redis is down
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
<<<<<<< HEAD
		{RedisController: rc},
		{IsCache: true, RedisController: rc},
		{IsAnalytics: true, RedisController: rc},
	}
	var ok bool
	for _, v := range c {
		if !rc.connectSingleton(v.IsCache, v.IsAnalytics, *conf) {
			break
		}

		if !clusterConnectionIsOpen(&v) {
			rc.redisUp.Store(false)
			break
=======
		{
			RedisController: rc,
		},
		{
			RedisController: rc,
			IsCache:         true,
		},
		{
			RedisController: rc,
			IsAnalytics:     true,
		},
	}

	// First time connecting to the clusters. We need this for the first connection (and avoid waiting 1second for the rc.statusCheck loop).
	for _, v := range c {
		rc.connectSingleton(v.IsCache, v.IsAnalytics, *conf)
		err := backoff.Retry(v.checkIsOpen, getExponentialBackoff())
		if err != nil {
			log.WithError(err).Errorf("Could not connect to Redis cluster after many attempts. Host(s): %v", getRedisAddrs(conf.Storage))
>>>>>>> ccecd4cd... [TT-8901] Preventing panics if cache_storage is down (#5065)
		}
		ok = true
	}
<<<<<<< HEAD
	rc.redisUp.Store(ok)
=======

	rc.redisUp.Store(true)

	defer func() {
		close(rc.reconnect)
		rc.disconnect()
	}()

	go rc.recoverLoop(ctx, onReconnect)

	// We need the ticker to constantly checking the connection status of Redis. If Redis gets down and up again, we should be able to recover.
	rc.statusCheck(ctx, conf, c)
}

// getExponentialBackoff returns a backoff.ExponentialBackOff with the following settings:
//   - Multiplier: 2
//   - MaxInterval: 10 seconds
//   - MaxElapsedTime: 0 (no limit)
func getExponentialBackoff() *backoff.ExponentialBackOff {
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.Multiplier = 2
	exponentialBackoff.MaxInterval = 10 * time.Second
	exponentialBackoff.MaxElapsedTime = 0

	return exponentialBackoff
}

// statusCheck will check the Redis status each second. If we transition from a disconnected to connected state, it will send a msg to the reconnect chan.
// This method will be constantly modifying the redisUp control flag.
func (rc *RedisController) statusCheck(ctx context.Context, conf *config.Config, clusters []RedisCluster) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

>>>>>>> ccecd4cd... [TT-8901] Preventing panics if cache_storage is down (#5065)
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
		if ok := rc.establishConnection(&x, conf); !ok {
			return false
		}
	}
	return true
}

func (rc *RedisController) establishConnection(v *RedisCluster, conf config.Config) bool {
	if !rc.connectSingleton(v.IsCache, v.IsAnalytics, conf) {
		return false
	}
	return clusterConnectionIsOpen(v)
}
