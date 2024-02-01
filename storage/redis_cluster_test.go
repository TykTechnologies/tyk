package storage

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/storage/temporal/model"
	tempmocks "github.com/TykTechnologies/storage/temporal/tempmocks"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"

	"github.com/stretchr/testify/mock"
)

var rc *ConnectionHandler

func TestMain(m *testing.M) {
	conf, err := config.New()
	if err != nil {
		panic(err)
	}

	rc = NewConnectionHandler(context.Background())
	go rc.Connect(context.Background(), nil, conf)

	timeout, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}

	os.Exit(m.Run())
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
		receiveFn := func(context.Context) (model.Message, error) {
			return nil, nil
		}
		err := cluster.handleReceive(ctx, receiveFn, nil)
		assert.NoError(t, err)
	})
}

func TestRedisClusterGetMultiKey(t *testing.T) {
	keys := []string{"first", "second"}
	r := RedisCluster{KeyPrefix: "test-cluster", ConnectionHandler: rc}

	r.DeleteAllKeys()

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
	storage := &RedisCluster{KeyPrefix: "test-", ConnectionHandler: rc}

	assert.True(t, storage.ConnectionHandler.isConnected(context.Background(), DefaultConn))

	storage.DeleteAllKeys()

	testKey := "test-key"
	testValue := "test-value"
	storage.SetKey(testKey, testValue, 0)
	key, err := storage.GetKey(testKey)
	assert.Equal(t, testValue, key)
	assert.Equal(t, nil, err)

	// testing if GetExp returns -2 for non existent keys
	ttl, errGetExp := storage.GetExp(testKey + "random")
	assert.Equal(t, int64(-2), ttl)
	assert.Equal(t, nil, errGetExp)

	// testing if GetExp returns -1 for keys without expiration
	ttl, errGetExp = storage.GetExp(testKey)
	assert.Equal(t, int64(-1), ttl)
	assert.Equal(t, nil, errGetExp)

	// Testing if SetExp actually sets the expiration.
	errSetExp := storage.SetExp(testKey, 40)
	assert.Equal(t, nil, errSetExp)
	ttl, errGetExp = storage.GetExp(testKey)
	assert.Equal(t, int64(40), ttl)
	assert.Equal(t, nil, errGetExp)
}

func TestLock(t *testing.T) {
	t.Run("redis down", func(t *testing.T) {
		mockedKv := tempmocks.NewKeyValue(t)
		redisCluster := &RedisCluster{
			ConnectionHandler: NewConnectionHandler(context.Background()),
			kvStorage:         mockedKv,
		}

		redisCluster.ConnectionHandler.storageUp.Store(false)

		ok, err := redisCluster.Lock("lock-key", time.Second)
		assert.Error(t, err)
		assert.False(t, ok)
		mockedKv.AssertExpectations(t)
	})

	t.Run("lock success", func(t *testing.T) {
		mockedKv := tempmocks.NewKeyValue(t)
		mockedKv.On("SetIfNotExist", mock.Anything, "lock-key", "1", time.Second).Return(true, nil)

		redisCluster := &RedisCluster{
			ConnectionHandler: NewConnectionHandler(context.Background()),
			kvStorage:         mockedKv,
		}
		redisCluster.ConnectionHandler.storageUp.Store(true)

		ok, err := redisCluster.Lock("lock-key", time.Second)
		assert.NoError(t, err)
		assert.True(t, ok)
		mockedKv.AssertExpectations(t)
	})

	t.Run("lock failure", func(t *testing.T) {
		mockedKv := tempmocks.NewKeyValue(t)
		mockedKv.On("SetIfNotExist", mock.Anything, "lock-key", "1", time.Second).Return(false, nil)

		redisCluster := &RedisCluster{
			ConnectionHandler: NewConnectionHandler(context.Background()),
			kvStorage:         mockedKv,
		}
		redisCluster.ConnectionHandler.storageUp.Store(true)

		ok, err := redisCluster.Lock("lock-key", time.Second)
		assert.NoError(t, err)
		assert.False(t, ok)
		mockedKv.AssertExpectations(t)
	})

	t.Run("lock error", func(t *testing.T) {
		mockedKv := tempmocks.NewKeyValue(t)
		mockedKv.On("SetIfNotExist", mock.Anything, "lock-key", "1", time.Second).Return(false, errors.ErrUnsupported)

		redisCluster := &RedisCluster{
			ConnectionHandler: NewConnectionHandler(context.Background()),
			kvStorage:         mockedKv,
		}
		redisCluster.ConnectionHandler.storageUp.Store(true)

		ok, err := redisCluster.Lock("lock-key", time.Second)
		assert.Equal(t, errors.ErrUnsupported, err)
		assert.False(t, ok)
		mockedKv.AssertExpectations(t)
	})
}

func TestInternalStorages(t *testing.T) {
	tcs := []struct {
		name         string
		getStorageFn func(storage *RedisCluster) (interface{}, error)
	}{
		{
			name: "KeyValue",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.kv()
			},
		},
		{
			name: "Set",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.set()
			},
		},
		{
			name: "Client",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.Client()
			},
		},
		{
			name: "Queue",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.queue()
			},
		},
		{
			name: "List",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.list()
			},
		},
		{
			name: "SortedSet",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.sortedSet()
			},
		},
		{
			name: "Flusher",
			getStorageFn: func(storage *RedisCluster) (interface{}, error) {
				return storage.flusher()
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name+" valid client", func(t *testing.T) {
			storage := &RedisCluster{ConnectionHandler: rc}
			obj, err := tc.getStorageFn(storage)

			assert.NoError(t, err)
			assert.NotNil(t, obj)
		})
		t.Run(tc.name+" connection disabled", func(t *testing.T) {
			storage := &RedisCluster{ConnectionHandler: rc}
			storage.ConnectionHandler.storageUp.Store(false)
			defer storage.ConnectionHandler.storageUp.Store(true)
			obj, err := tc.getStorageFn(storage)

			assert.Error(t, err)
			assert.Nil(t, obj)
		})
		t.Run(tc.name+" connection not init", func(t *testing.T) {
			storage := &RedisCluster{ConnectionHandler: NewConnectionHandler(context.Background())}
			storage.ConnectionHandler.storageUp.Store(true)
			obj, err := tc.getStorageFn(storage)

			assert.Equal(t, err, ErrStorageConn)
			assert.Nil(t, obj)
		})
	}
}

func TestGetKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		_, err := storage.GetKey("key")
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Get", mock.Anything, "key").Return("value", nil)

		val, err := storage.GetKey("key")
		assert.NoError(t, err)
		assert.Equal(t, "value", val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Get", mock.Anything, "prefix:key").Return("value", nil)

		val, err := storage.GetKey("key")
		assert.NoError(t, err)
		assert.Equal(t, "value", val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Get", mock.Anything, "key").Return("", errors.New("key not found"))

		val, err := storage.GetKey("key")
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		assert.Equal(t, "", val)
		mockKv.AssertExpectations(t)
	})
}

func TestGetMultiKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		defer storage.ConnectionHandler.storageUp.Store(true)

		_, err := storage.GetMultiKey([]string{"key1", "key"})
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetMulti", mock.Anything, []string{"key1", "key"}).Return([]interface{}{"<nil>", "value"}, nil)

		val, err := storage.GetMultiKey([]string{"key1", "key"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"", "value"}, val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetMulti", mock.Anything, []string{"prefix:key1", "prefix:key"}).Return([]interface{}{"<nil>", "value"}, nil)

		val, err := storage.GetMultiKey([]string{"key1", "key"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"", "value"}, val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetMulti", mock.Anything, []string{"key"}).Return([]interface{}{}, errors.New("key not found"))

		val, err := storage.GetMultiKey([]string{"key"})
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		assert.Equal(t, []string(nil), val)
		mockKv.AssertExpectations(t)
	})
}

func TestGetKeyTTL(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		_, err := storage.GetKeyTTL("key")
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "key").Return(int64(10), nil)

		val, err := storage.GetKeyTTL("key")
		assert.NoError(t, err)
		assert.Equal(t, int64(10), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "prefix:key").Return(int64(10), nil)

		val, err := storage.GetKeyTTL("key")
		assert.NoError(t, err)
		assert.Equal(t, int64(10), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "key").Return(int64(0), ErrKeyNotFound)

		val, err := storage.GetKeyTTL("key")
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		assert.Equal(t, int64(0), val)
		mockKv.AssertExpectations(t)
	})
}

func TestGetRawKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		_, err := storage.GetRawKey("key")
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Get", mock.Anything, "key").Return("value", nil)

		val, err := storage.GetRawKey("key")
		assert.NoError(t, err)
		assert.Equal(t, "value", val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Get", mock.Anything, "key").Return("", ErrKeyNotFound)

		val, err := storage.GetRawKey("key")
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		assert.Equal(t, "", val)
		mockKv.AssertExpectations(t)
	})
}

func TestGetExp(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		_, err := storage.GetExp("key")
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "key").Return(int64(10), nil)

		val, err := storage.GetExp("key")
		assert.NoError(t, err)
		assert.Equal(t, int64(10), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "prefix:key").Return(int64(10), nil)

		val, err := storage.GetExp("key")
		assert.NoError(t, err)
		assert.Equal(t, int64(10), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("TTL", mock.Anything, "key").Return(int64(0), ErrKeyNotFound)

		val, err := storage.GetExp("key")
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		assert.Equal(t, int64(0), val)
		mockKv.AssertExpectations(t)
	})
}

func TestSetExp(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		err := storage.SetExp("key", 10)
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Expire", mock.Anything, "key", time.Duration(10*time.Second)).Return(nil)

		err := storage.SetExp("key", 10)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Expire", mock.Anything, "prefix:key", time.Duration(-1*time.Second)).Return(nil)

		err := storage.SetExp("key", -1)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Expire", mock.Anything, "key", time.Duration(-1*time.Second)).Return(ErrKeyNotFound)

		err := storage.SetExp("key", -1)
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		mockKv.AssertExpectations(t)
	})
}

func TestSetKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		err := storage.SetKey("key", "value", 10)
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "key", "value", time.Duration(10*time.Second)).Return(nil)

		err := storage.SetKey("key", "value", 10)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "prefix:key", "value", time.Duration(-1*time.Second)).Return(nil)

		err := storage.SetKey("key", "value", -1)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "key", "value", time.Duration(-1*time.Second)).Return(ErrKeyNotFound)

		err := storage.SetKey("key", "value", -1)
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		mockKv.AssertExpectations(t)
	})
}

func TestSetRawKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		err := storage.SetRawKey("key", "value", 10)
		assert.Error(t, err)
		assert.Equal(t, ErrRedisIsDown, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "key", "value", time.Duration(10*time.Second)).Return(nil)

		err := storage.SetRawKey("key", "value", 10)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("set ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "key", "value", time.Duration(-1*time.Second)).Return(nil)

		err := storage.SetRawKey("key", "value", -1)
		assert.NoError(t, err)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Set", mock.Anything, "key", "value", time.Duration(-1*time.Second)).Return(ErrKeyNotFound)

		err := storage.SetRawKey("key", "value", -1)
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
		mockKv.AssertExpectations(t)
	})
}

func TestDecrement(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		storage.Decrement("key")
		mockKv.AssertExpectations(t)
	})
	t.Run("decrement ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Decrement", mock.Anything, "key").Return(int64(1), nil)

		storage.Decrement("key")
		mockKv.AssertExpectations(t)
	})
	t.Run("decrement ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Decrement", mock.Anything, "prefix:key").Return(int64(1), nil)

		storage.Decrement("key")
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Decrement", mock.Anything, "key").Return(int64(1), ErrKeyNotFound)

		storage.Decrement("key")
		mockKv.AssertExpectations(t)
	})
}

func TestIncrememntWithExpire(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		val := storage.IncrememntWithExpire("key", 10)
		assert.Equal(t, int64(0), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("increment with expire not first increment", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Increment", mock.Anything, "key").Return(int64(2), nil)

		val := storage.IncrememntWithExpire("key", 10)
		assert.Equal(t, int64(2), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("increment with expire and prefix not first increment", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		// always rawkey on this
		mockKv.On("Increment", mock.Anything, "key").Return(int64(2), nil)

		val := storage.IncrememntWithExpire("key", 10)
		assert.Equal(t, int64(2), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("increment with expire first increment", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Increment", mock.Anything, "key").Return(int64(1), nil)
		mockKv.On("Expire", mock.Anything, "key", time.Duration(10*time.Second)).Return(nil)

		val := storage.IncrememntWithExpire("key", 10)
		assert.Equal(t, int64(1), val)
		mockKv.AssertExpectations(t)
	})

	t.Run("increment without expire first increment", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Increment", mock.Anything, "key").Return(int64(1), nil)

		val := storage.IncrememntWithExpire("key", 0)
		assert.Equal(t, int64(1), val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Increment", mock.Anything, "key").Return(int64(0), ErrKeyNotFound)

		val := storage.IncrememntWithExpire("key", 0)
		assert.Equal(t, int64(0), val)
		mockKv.AssertExpectations(t)
	})
}

func TestGetKeys(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		defer storage.ConnectionHandler.storageUp.Store(true)

		res := storage.GetKeys("filter")
		assert.Equal(t, []string(nil), res)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found without prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Keys", mock.Anything, "key*").Return([]string{"key1", "key2"}, nil)

		val := storage.GetKeys("key")
		assert.Equal(t, []string{"key1", "key2"}, val)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found with prefix but without filter", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Keys", mock.Anything, "prefix:*").Return([]string{"prefix:key1", "prefix:key2"}, nil)

		val := storage.GetKeys("")
		assert.Equal(t, []string{"key1", "key2"}, val)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Keys", mock.Anything, "prefix:key*").Return([]string{"prefix:key1", "prefix:key2"}, nil)

		val := storage.GetKeys("key")
		assert.Equal(t, []string{"key1", "key2"}, val)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Keys", mock.Anything, "key*").Return([]string{}, errors.New("key not found"))

		val := storage.GetKeys("key")
		assert.Equal(t, []string(nil), val)
		mockKv.AssertExpectations(t)
	})
}
