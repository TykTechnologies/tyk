package storage

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func init() {
	conf := config.Default
	rc := RedisController{ctx: context.Background()}

	go rc.ConnectToRedis(context.Background(), nil, &conf)
	for {
		if rc.Connected() {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestRedisClusterGetMultiKey(t *testing.T) {

	rc := RedisController{ctx: context.Background()}
	keys := []string{"first", "second"}
	r := RedisCluster{KeyPrefix: "test-cluster", RedisController: &rc}
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
	rc := RedisController{ctx: context.Background()}
	storage := &RedisCluster{KeyPrefix: "test-", RedisController: &rc}

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
