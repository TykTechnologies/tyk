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

	ctx, cancel := context.WithTimeout(rc.ctx, 5*time.Second)
	defer cancel()

	if !rc.WaitConnect(ctx) {
		panic("Can't reconnect to redis after disable")
	}
	rc.reconnect <- struct{}{}
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
// onReconnect will be called when we have established a successful redis reconnection
func (rc *RedisController) ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config) {
	if onReconnect == nil {
		onReconnect = func() {
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

	// First time connecting to the clusters. We need this for the first connection (and avoid waiting 1second for the rc.statusCheck loop).
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

	defer func() {
		close(rc.reconnect)
		rc.disconnect()
	}()

	go rc.recoverLoop(ctx, onReconnect)

	// We need the ticker to constantly checking the connection status of Redis. If Redis gets down and up again, we should be able to recover.
	rc.statusCheck(ctx, conf, c)
}

//statusCheck will check the Redis status each second. If we transition from a disconnected to connected state, it will send a msg to the reconnect chan.
// This method will be constantly modifying the redisUp control flag.
func (rc *RedisController) statusCheck(ctx context.Context, conf *config.Config, clusters []RedisCluster) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			//if we disabled redis - we don't want to check anything
			if !rc.enabled() {
				continue
			}

			//we check if the clusters are initialised and if connections are open
			connected := rc.connectCluster(*conf, clusters...)

			//we check if we are already connected connected
			alreadyConnected := rc.Connected()

			//store the actual status of redis
			rc.redisUp.Store(connected)

			//if we weren't alerady connected but now we are connected, we trigger the reconnect
			if !alreadyConnected && connected {
				rc.reconnect <- struct{}{}
			}
		}
	}
}

// recoverLoop will be checking waiting for a rc.reconnect signal to trigger the onReconnect func.
func (rc *RedisController) recoverLoop(ctx context.Context, onReconnect func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.reconnect:
			onReconnect()
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
