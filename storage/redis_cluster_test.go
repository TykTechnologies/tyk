package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

var rc *RedisController

func init() {
	conf, err := config.New()
	if err != nil {
		panic(err)
	}

	rc = NewRedisController(context.Background())
	go rc.ConnectToRedis(context.Background(), nil, conf)
	for {
		if rc.Connected() {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandleMessage(t *testing.T) {
	cluster := &RedisCluster{}

	testErr := errors.New("Test error (expected)")

	t.Run("handle message without err", func(t *testing.T) {
		ok := false
		err := cluster.handleMessage(nil, nil, func(_ interface{}) {
			ok = true
		})
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("handle message with err", func(t *testing.T) {
		got := cluster.handleMessage(nil, testErr, nil)
		assert.Equal(t, testErr, got)
	})

	t.Run("handle message with err coalescing", func(t *testing.T) {
		err := errors.New("Test error (expected): use of closed network connection")
		want := cluster.handleMessage(nil, err, nil)
		assert.Equal(t, redis.ErrClosed, want)
	})
}

func TestHandleReceive(t *testing.T) {
	cluster := &RedisCluster{}
	ctx := context.Background()

	t.Run("handle receive without err", func(t *testing.T) {
		receiveFn := func(context.Context) (interface{}, error) {
			return nil, nil
		}
		err := cluster.handleReceive(ctx, receiveFn, nil)
		assert.NoError(t, err)
	})
}

func TestRedisClusterGetMultiKey(t *testing.T) {

	keys := []string{"first", "second"}
	r := RedisCluster{KeyPrefix: "test-cluster", RedisController: rc}
	for _, v := range keys {
		r.DeleteKey(v)
	}
	_, err := r.GetMultiKey(keys)
	if err != ErrKeyNotFound {
		t.Errorf("expected %v got %v", ErrKeyNotFound, err)
	}
	err = r.SetKey(keys[0], keys[0], 0)
	if err != nil {
		t.Fatal(err)
	}

	v, err := r.GetMultiKey([]string{"first", "second"})
	if err != nil {
		t.Fatal(err)
	}
	if v[0] != keys[0] {
		t.Errorf("expected %s got %s", keys[0], v[0])
	}
}

func TestRedisAddressConfiguration(t *testing.T) {

	t.Run("Host but no port", func(t *testing.T) {
		cfg := config.StorageOptionsConf{Host: "host"}
		if len(getRedisAddrs(cfg)) != 0 {
			t.Fatal("Port is 0, there is no valid addr")
		}
	})

	t.Run("Port but no host", func(t *testing.T) {
		cfg := config.StorageOptionsConf{Port: 30000}

		addrs := getRedisAddrs(cfg)
		if addrs[0] != ":30000" || len(addrs) != 1 {
			t.Fatal("Port is valid, it is a valid addr")
		}
	})

	t.Run("addrs parameter should have precedence", func(t *testing.T) {
		cfg := config.StorageOptionsConf{Host: "host", Port: 30000}

		addrs := getRedisAddrs(cfg)
		if addrs[0] != "host:30000" || len(addrs) != 1 {
			t.Fatal("Wrong address")
		}

		cfg.Addrs = []string{"override:30000"}

		addrs = getRedisAddrs(cfg)
		if addrs[0] != "override:30000" || len(addrs) != 1 {
			t.Fatal("Wrong address")
		}
	})

	t.Run("Default addresses", func(t *testing.T) {
		opts := &redis.UniversalOptions{}
		simpleOpts := opts.Simple()

		if simpleOpts.Addr != "127.0.0.1:6379" {
			t.Fatal("Wrong default single node address")
		}

		opts.Addrs = []string{}
		clusterOpts := opts.Cluster()

		if clusterOpts.Addrs[0] != "127.0.0.1:6379" || len(clusterOpts.Addrs) != 1 {
			t.Fatal("Wrong default cluster mode address")
		}

		opts.Addrs = []string{}
		failoverOpts := opts.Failover()

		if failoverOpts.SentinelAddrs[0] != "127.0.0.1:26379" || len(failoverOpts.SentinelAddrs) != 1 {
			t.Fatal("Wrong default sentinel mode address")
		}
	})
}

func TestRedisExpirationTime(t *testing.T) {
	storage := &RedisCluster{KeyPrefix: "test-", RedisController: rc}

	testKey := "test-key"
	testValue := "test-value"
	storage.SetKey(testKey, testValue, 0)
	key, err := storage.GetKey(testKey)
	assert.Equal(t, testValue, key)
	assert.Equal(t, nil, err)

	//testing if GetExp returns -2 for non existent keys
	ttl, errGetExp := storage.GetExp(testKey + "random")
	assert.Equal(t, int64(-2), ttl)
	assert.Equal(t, nil, errGetExp)

	//testing if GetExp returns -1 for keys without expiration
	ttl, errGetExp = storage.GetExp(testKey)
	assert.Equal(t, int64(-1), ttl)
	assert.Equal(t, nil, errGetExp)

	//Testing if SetExp actually sets the expiration.
	errSetExp := storage.SetExp(testKey, 40)
	assert.Equal(t, nil, errSetExp)
	ttl, errGetExp = storage.GetExp(testKey)
	assert.Equal(t, int64(40), ttl)
	assert.Equal(t, nil, errGetExp)

}

func TestSingleton(t *testing.T) {
	r := &RedisCluster{}
	instance, err := r.singleton()
	assert.NotNil(t, err)
	assert.EqualError(t, err, "Error trying to get singleton instance: RedisController is nil")
	assert.Nil(t, instance)

	r.RedisController = rc

	instance, err = r.singleton()
	assert.Nil(t, err)
	assert.NotNil(t, instance)
	cmd := instance.Ping(context.Background())
	assert.NotNil(t, cmd)
	assert.NoError(t, cmd.Err())

	r.IsAnalytics = true
	analyticsInstance, err := r.singleton()
	assert.Nil(t, err)
	assert.NotNil(t, analyticsInstance)
	cmd = analyticsInstance.Ping(context.Background())
	assert.NotNil(t, cmd)
	assert.NoError(t, cmd.Err())
	assert.NotEqual(t, instance, analyticsInstance)

	r.IsCache = true
	cacheInstance, err := r.singleton()
	assert.Nil(t, err)
	assert.NotNil(t, cacheInstance)
	cmd = cacheInstance.Ping(context.Background())
	assert.NotNil(t, cmd)
	assert.NoError(t, cmd.Err())
	assert.NotEqual(t, instance, cacheInstance)
	assert.NotEqual(t, analyticsInstance, cacheInstance)

	cacheInstance2, err := r.singleton()
	assert.Nil(t, err)
	assert.NotNil(t, cacheInstance)
	cmd = cacheInstance.Ping(context.Background())
	assert.NotNil(t, cmd)
	assert.NoError(t, cmd.Err())
	assert.Equal(t, cacheInstance, cacheInstance2)
}

func TestCheckIsOpen(t *testing.T) {
	conf, err := config.New()
	assert.NoError(t, err)

	rc := NewRedisController(context.Background())
	cluster := RedisCluster{
		RedisController: rc,
	}

	err = cluster.checkIsOpen()
	assert.Error(t, err)
	assert.EqualError(t, err, ErrRedisIsDown.Error())
	assert.True(t, rc.connectSingleton(false, false, *conf))
	assert.NoError(t, cluster.checkIsOpen())
}
