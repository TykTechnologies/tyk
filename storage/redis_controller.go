package storage

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

type RedisController struct {
	poolSingle    RedisDriver
	poolCache     RedisDriver
	poolAnalytics RedisDriver

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

// Disable allows to dynamically enable/disable talking with storage.
func (rc *RedisController) Disable(disable bool) {
	if disable {
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

// DisableRedis is deprecated, use Disable.
func (rc *RedisController) DisableRedis(disable bool) {
	rc.Disable(disable)
}

func (rc *RedisController) enabled() bool {
	ok, _ := rc.disableRedis.Load().(bool)
	return ok
}

// Connected returns true if we are connected to redis.
func (rc *RedisController) Connected() bool {
	ok, _ := rc.redisUp.Load().(bool)
	return ok
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

// disconnect all redis clients created
func (rc *RedisController) disconnect() {
	for _, v := range []RedisDriver{
		rc.poolCache,
		rc.poolAnalytics,
		rc.poolSingle,
	} {
		defer v.Close()
	}
}

// Deprecated
func (rc *RedisController) ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config) {
	rc.Connect(ctx, onReconnect, conf)
}

func (rc *RedisController) Context() context.Context {
	return rc.ctx
}

// Connect starts a go routine that periodically tries to connect to storage.
//
// onReconnect will be called when we have established a successful redis reconnection
func (rc *RedisController) Connect(ctx context.Context, onReconnect func(), conf *config.Config) {
	log.Infof("Connecting redis tests to host=%s:%d, type=%s", conf.Storage.Host, conf.Storage.Port, conf.Storage.Type)

	if onReconnect == nil {
		onReconnect = func() {
			// an empty function to avoid repeated nil checks below
		}
	}

	rc.initClusterPool(&rc.poolSingle, false, false, conf)
	rc.initClusterPool(&rc.poolCache, true, false, conf)
	rc.initClusterPool(&rc.poolAnalytics, false, true, conf)

	clusters := []*RedisCluster{
		&RedisCluster{
			RedisController: rc,
		},
		&RedisCluster{
			IsCache:         true,
			RedisController: rc,
		},
		&RedisCluster{
			IsAnalytics:     true,
			RedisController: rc,
		},
	}

	// First time connecting to the clusters.
	// We need this for the first connection (and avoid waiting 1second for the rc.statusCheck loop).
	up := rc.connectCluster(ctx, clusters)
	rc.redisUp.Store(up)

	defer func() {
		close(rc.reconnect)
		rc.disconnect()
	}()

	go rc.recoverLoop(ctx, onReconnect)

	// We need the ticker to constantly checking the connection status of Redis.
	// If Redis gets down and up again, we should be able to recover.
	rc.statusCheck(ctx, clusters)
}

// initClusterPool will create a new RedisClient for the passed pool variable.
func (rc *RedisController) initClusterPool(pool *RedisDriver, cache, analytics bool, conf *config.Config) {
	if *pool == nil {
		*pool = NewRedisClusterPool(cache, analytics, *conf)
	}
}

// statusCheck will check the Redis status each second.
//
// If we transition from a disconnected to connected state, it will send
// a msg to the reconnect chan. This method will be constantly modifying
// the redisUp control flag.
func (rc *RedisController) statusCheck(ctx context.Context, clusters []*RedisCluster) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// if we disabled redis - we don't want to check anything
			if !rc.enabled() {
				continue
			}

			// we check if the clusters are initialised and if connections are open
			connected := rc.connectCluster(ctx, clusters)

			// we check if we are already connected connected
			alreadyConnected := rc.Connected()

			// store the actual status of redis
			rc.redisUp.Store(connected)

			// if we weren't alerady connected but now we are connected, we trigger the reconnect
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

// connectCluster will go over each *RedisCluster and return true if all are online.
func (rc *RedisController) connectCluster(ctx context.Context, v []*RedisCluster) bool {
	ok := true
	for _, x := range v {
		ok = rc.establishConnection(ctx, x) && ok
	}
	return ok
}

// establishConnection issues a Ping() over a RedisCluster individual RedisDriver to verify connectivity.
func (rc *RedisController) establishConnection(ctx context.Context, v *RedisCluster) bool {
	return rc.singleton(v.IsCache, v.IsAnalytics).Ping(ctx) == nil
}

// singleton returns a desired RedisDriver instance. Instances are created in Connect().
func (rc *RedisController) singleton(cache, analytics bool) RedisDriver {
	switch {
	case cache:
		return rc.poolCache
	case analytics:
		return rc.poolAnalytics
	default:
		return rc.poolSingle
	}
}
