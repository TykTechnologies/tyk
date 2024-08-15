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

func TestRedisClusterGetConnectionHandler(t *testing.T) {
	// Scenario 1: RedisController is not nil.
	t.Run("with RedisController", func(t *testing.T) {
		connHandler := NewConnectionHandler(context.Background())
		mockRedisController := &RedisController{
			connection: connHandler,
		}
		redisCluster := &RedisCluster{
			RedisController: mockRedisController,
		}

		got := redisCluster.getConnectionHandler()
		if got != connHandler {
			t.Errorf("getConnectionHandler() with RedisController = %v, want %v", got, connHandler)
		}
	})

	// Scenario 2: RedisController is nil.
	t.Run("without RedisController", func(t *testing.T) {
		connHandler := NewConnectionHandler(context.Background())
		redisCluster := &RedisCluster{
			ConnectionHandler: connHandler,
		}

		got := redisCluster.getConnectionHandler()
		if got != connHandler {
			t.Errorf("getConnectionHandler() without RedisController = %v, want %v", got, connHandler)
		}
	})
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
	if !errors.Is(err, ErrKeyNotFound) {
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

func TestGetKeysAndValuesWithFilter(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		defer storage.ConnectionHandler.storageUp.Store(true)

		res := storage.GetKeysAndValuesWithFilter("filter")
		assert.Equal(t, map[string]string(map[string]string(nil)), res)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found without prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "key").Return(map[string]interface{}{"key1": "value1", "key2": "value2"}, nil)

		res := storage.GetKeysAndValuesWithFilter("key")
		assert.Equal(t, map[string]string{"key1": "value1", "key2": "value2"}, res)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "prefix:key").Return(map[string]interface{}{"prefix:key1": "value1", "prefix:key2": "value2"}, nil)

		res := storage.GetKeysAndValuesWithFilter("key")
		assert.Equal(t, map[string]string{"key1": "value1", "key2": "value2"}, res)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found with prefix without filter", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "").Return(map[string]interface{}{"prefix:key1": "value1", "prefix:key2": "value2"}, nil)

		res := storage.GetKeysAndValuesWithFilter("")
		assert.Equal(t, map[string]string{"key1": "value1", "key2": "value2"}, res)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "test").Return(map[string]interface{}{}, ErrKeyNotFound)

		res := storage.GetKeysAndValuesWithFilter("test")
		assert.Equal(t, map[string]string(map[string]string(nil)), res)
		mockKv.AssertExpectations(t)
	})
}

func TestGetKeysAndValues(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		defer storage.ConnectionHandler.storageUp.Store(true)

		res := storage.GetKeysAndValues()
		assert.Equal(t, map[string]string(map[string]string(nil)), res)
		mockKv.AssertExpectations(t)
	})
	t.Run("keys found with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "").Return(map[string]interface{}{"prefix:key1": "value1", "prefix:key2": "value2"}, nil)

		res := storage.GetKeysAndValues()
		assert.Equal(t, map[string]string{"key1": "value1", "key2": "value2"}, res)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("GetKeysAndValuesWithFilter", mock.Anything, "").Return(map[string]interface{}{}, ErrKeyNotFound)

		res := storage.GetKeysAndValues()
		assert.Equal(t, map[string]string(map[string]string(nil)), res)
		mockKv.AssertExpectations(t)
	})
}

func TestDeleteKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteKey("key")
		assert.False(t, deleted)

		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Delete", mock.Anything, "key").Return(nil)
		mockKv.On("Exists", mock.Anything, "key").Return(true, nil)

		deleted := storage.DeleteKey("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Delete", mock.Anything, "prefix:key").Return(nil)
		mockKv.On("Exists", mock.Anything, "prefix:key").Return(true, nil)

		deleted := storage.DeleteKey("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Exists", mock.Anything, "key").Return(false, nil)

		deleted := storage.DeleteKey("key")
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})

	t.Run("error deleting", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Exists", mock.Anything, "key").Return(true, nil)
		mockKv.On("Delete", mock.Anything, "key").Return(errors.New("test"))

		deleted := storage.DeleteKey("key")
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
}

func TestDeleteAllKeys(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockFlusher := tempmocks.NewFlusher(t)
		storage.flusherStorage = mockFlusher
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteAllKeys()
		assert.False(t, deleted)

		mockFlusher.AssertExpectations(t)
	})
	t.Run("flush ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockFlusher := tempmocks.NewFlusher(t)
		storage.flusherStorage = mockFlusher
		mockFlusher.On("FlushAll", mock.Anything).Return(nil)

		deleted := storage.DeleteAllKeys()
		assert.True(t, deleted)
		mockFlusher.AssertExpectations(t)
	})
	t.Run("err flushing", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockFlusher := tempmocks.NewFlusher(t)
		storage.flusherStorage = mockFlusher
		mockFlusher.On("FlushAll", mock.Anything).Return(errors.New("err flushing"))

		deleted := storage.DeleteAllKeys()
		assert.False(t, deleted)
		mockFlusher.AssertExpectations(t)
	})
}

func TestDeleteRawKey(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteRawKey("key")
		assert.False(t, deleted)

		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Delete", mock.Anything, "key").Return(nil)

		deleted := storage.DeleteRawKey("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Delete", mock.Anything, "key").Return(nil)

		deleted := storage.DeleteRawKey("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("Delete", mock.Anything, "key").Return(ErrKeyNotFound)

		deleted := storage.DeleteRawKey("key")
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
}

func TestDeleteScanMatch(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteScanMatch("key")
		assert.False(t, deleted)

		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteScanMatch", mock.Anything, "key").Return(int64(3), nil)

		deleted := storage.DeleteScanMatch("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteScanMatch", mock.Anything, "key").Return(int64(3), nil)

		deleted := storage.DeleteScanMatch("key")
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteScanMatch", mock.Anything, "key").Return(int64(0), ErrKeyNotFound)

		deleted := storage.DeleteScanMatch("key")
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
}

func TestDeleteRawKeys(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteRawKeys([]string{"key"})
		assert.False(t, deleted)

		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"key", "key2"}).Return(int64(3), nil)

		deleted := storage.DeleteRawKeys([]string{"key", "key2"})
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"key", "key2"}).Return(int64(3), nil)

		deleted := storage.DeleteRawKeys([]string{"key", "key2"})
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})

	t.Run("delete ok - but none deleted", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"key", "key2"}).Return(int64(0), nil)

		deleted := storage.DeleteRawKeys([]string{"key", "key2"})
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("error deleting", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, mock.Anything).Return(int64(0), ErrKeyNotFound)

		deleted := storage.DeleteRawKeys([]string{"key"})
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
}

func TestDeleteKeys(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		defer storage.ConnectionHandler.storageUp.Store(true)

		deleted := storage.DeleteKeys([]string{"key"})
		assert.False(t, deleted)

		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"key", "key2"}).Return(int64(3), nil)

		deleted := storage.DeleteKeys([]string{"key", "key2"})
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("delete ok with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"prefix:key", "prefix:key2"}).Return(int64(3), nil)

		deleted := storage.DeleteKeys([]string{"key", "key2"})
		assert.True(t, deleted)
		mockKv.AssertExpectations(t)
	})

	t.Run("delete ok - but none deleted", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, []string{"prefix:key", "prefix:key2"}).Return(int64(0), nil)

		deleted := storage.DeleteKeys([]string{"key", "key2"})
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
	t.Run("error deleting", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		mockKv.On("DeleteKeys", mock.Anything, mock.Anything).Return(int64(0), ErrKeyNotFound)

		deleted := storage.DeleteKeys([]string{"key"})
		assert.False(t, deleted)
		mockKv.AssertExpectations(t)
	})
}

func TestGetAndDeleteSet(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		defer storage.ConnectionHandler.storageUp.Store(true)

		result := storage.GetAndDeleteSet("key")
		assert.Nil(t, result)
		mockList.AssertExpectations(t)
	})
	t.Run("get and delete set", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Pop", mock.Anything, fixedKey, int64(-1)).Return([]string{"value1", "value2"}, nil)

		result := storage.GetAndDeleteSet("key")
		assert.Equal(t, []interface{}{"value1", "value2"}, result)
		mockList.AssertExpectations(t)
	})
	t.Run("get and delete set with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Pop", mock.Anything, fixedKey, int64(-1)).Return([]string{"value1", "value2"}, nil)

		result := storage.GetAndDeleteSet("key")
		assert.Equal(t, []interface{}{"value1", "value2"}, result)
		mockList.AssertExpectations(t)
	})
	t.Run("empty set", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Pop", mock.Anything, fixedKey, int64(-1)).Return([]string{}, nil)

		result := storage.GetAndDeleteSet("key")
		assert.Equal(t, []interface{}{}, result)
		mockList.AssertExpectations(t)
	})
	t.Run("error popping set", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Pop", mock.Anything, fixedKey, int64(-1)).Return(nil, errors.New("error popping set"))

		result := storage.GetAndDeleteSet("key")
		assert.Nil(t, result)
		mockList.AssertExpectations(t)
	})
}

func TestAppendToSet(t *testing.T) {
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		defer storage.ConnectionHandler.storageUp.Store(true)

		storage.AppendToSet(keyName, value)
		mockList.AssertExpectations(t)
	})
	t.Run("append to set", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Append", mock.Anything, false, fixedKey, []byte(value)).Return(nil)

		storage.AppendToSet(keyName, value)
		mockList.AssertExpectations(t)
	})
	t.Run("append to set with prefix", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc, KeyPrefix: "prefix:"}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Append", mock.Anything, false, fixedKey, []byte(value)).Return(nil)

		storage.AppendToSet(keyName, value)
		mockList.AssertExpectations(t)
	})
	t.Run("error appending to set", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Append", mock.Anything, false, fixedKey, []byte(value)).Return(errors.New("error appending to set"))

		storage.AppendToSet(keyName, value)
		mockList.AssertExpectations(t)
	})
}

func TestExists(t *testing.T) {
	t.Run("exists true", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockKv.On("Exists", mock.Anything, fixedKey).Return(true, nil)

		exists, err := storage.Exists(keyName)
		assert.NoError(t, err)
		assert.True(t, exists)
		mockKv.AssertExpectations(t)
	})
	t.Run("exists false", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockKv.On("Exists", mock.Anything, fixedKey).Return(false, nil)

		exists, err := storage.Exists(keyName)
		assert.NoError(t, err)
		assert.False(t, exists)
		mockKv.AssertExpectations(t)
	})
	t.Run("storage error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockKv.On("Exists", mock.Anything, fixedKey).Return(false, errors.New("storage error"))

		exists, err := storage.Exists(keyName)
		assert.Error(t, err)
		assert.False(t, exists)
		mockKv.AssertExpectations(t)
	})
	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		_, err := storage.Exists("key")
		assert.Error(t, err)
	})
}

func TestRemoveFromList(t *testing.T) {
	t.Run("remove from list success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Remove", mock.Anything, fixedKey, int64(0), value).Return(int64(1), nil)

		err := storage.RemoveFromList(keyName, value)
		assert.NoError(t, err)
		mockList.AssertExpectations(t)
	})

	t.Run("remove from list key not found", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Remove", mock.Anything, fixedKey, int64(0), value).Return(int64(0), nil)

		err := storage.RemoveFromList(keyName, value)
		assert.NoError(t, err)
		mockList.AssertExpectations(t)
	})

	t.Run("remove from list error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockList.On("Remove", mock.Anything, fixedKey, int64(0), value).Return(int64(0), errors.New("error removing from list"))

		err := storage.RemoveFromList(keyName, value)
		assert.Error(t, err)
		mockList.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		err := storage.RemoveFromList("key", "value")
		assert.Error(t, err)
	})
}

func TestGetListRange(t *testing.T) {
	t.Run("get list range success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		from := int64(0)
		to := int64(10)
		fixedKey := storage.fixKey(keyName)
		expectedRange := []string{"value1", "value2", "value3"}
		mockList.On("Range", mock.Anything, fixedKey, from, to).Return(expectedRange, nil)

		result, err := storage.GetListRange(keyName, from, to)
		assert.NoError(t, err)
		assert.Equal(t, expectedRange, result)
		mockList.AssertExpectations(t)
	})

	t.Run("get list range empty", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		from := int64(0)
		to := int64(10)
		fixedKey := storage.fixKey(keyName)
		mockList.On("Range", mock.Anything, fixedKey, from, to).Return([]string{}, nil)

		result, err := storage.GetListRange(keyName, from, to)
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockList.AssertExpectations(t)
	})

	t.Run("get list range error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		from := int64(0)
		to := int64(10)
		fixedKey := storage.fixKey(keyName)
		mockList.On("Range", mock.Anything, fixedKey, from, to).Return(nil, errors.New("error getting list range"))

		result, err := storage.GetListRange(keyName, from, to)
		assert.Error(t, err)
		assert.Nil(t, result)
		mockList.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		result, err := storage.GetListRange("key", 0, 10)
		assert.Error(t, err)
		assert.Equal(t, []string{}, result)
	})
}

func TestAppendToSetPipelined(t *testing.T) {
	t.Run("append to set pipelined success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		values := [][]byte{[]byte("value1"), []byte("value2")}
		fixedKey := storage.fixKey(keyName)
		mockList.On("Append", mock.Anything, true, fixedKey, values[0], values[1]).Return(nil)

		storage.AppendToSetPipelined(keyName, values)
		mockList.AssertExpectations(t)
	})

	t.Run("append to set pipelined with no values", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		values := [][]byte{}

		storage.AppendToSetPipelined(keyName, values)
		mockList.AssertExpectations(t)
	})

	t.Run("append to set pipelined error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockList := tempmocks.NewList(t)
		storage.listStorage = mockList
		keyName := "key"
		values := [][]byte{[]byte("value1"), []byte("value2")}
		fixedKey := storage.fixKey(keyName)
		mockList.On("Append", mock.Anything, true, fixedKey, values[0], values[1]).Return(errors.New("error appending to set"))

		storage.AppendToSetPipelined(keyName, values)
		mockList.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		storage.AppendToSetPipelined("key", [][]byte{[]byte("value")})
	})
}

func TestGetSet(t *testing.T) {
	t.Run("get set success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		expectedSet := map[string]string{"0": "value1", "1": "value2"}
		mockSet.On("Members", mock.Anything, fixedKey).Return([]string{"value1", "value2"}, nil)

		result, err := storage.GetSet(keyName)
		assert.NoError(t, err)
		assert.Equal(t, expectedSet, result)
		mockSet.AssertExpectations(t)
	})

	t.Run("get set empty", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("Members", mock.Anything, fixedKey).Return([]string{}, nil)

		result, err := storage.GetSet(keyName)
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockSet.AssertExpectations(t)
	})

	t.Run("get set error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("Members", mock.Anything, fixedKey).Return(nil, errors.New("error getting set"))

		result, err := storage.GetSet(keyName)
		assert.Error(t, err)
		assert.Nil(t, result)
		mockSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		result, err := storage.GetSet("key")
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestAddToSet(t *testing.T) {
	t.Run("add to set success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("AddMember", mock.Anything, fixedKey, value).Return(nil)

		storage.AddToSet(keyName, value)
		mockSet.AssertExpectations(t)
	})

	t.Run("add to set error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("AddMember", mock.Anything, fixedKey, value).Return(errors.New("error adding to set"))

		storage.AddToSet(keyName, value)
		mockSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)

		storage.AddToSet("key", "value")
		// Expect no calls to mockSet since the storage is disconnected
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		mockSet.AssertExpectations(t)
	})
}

func TestRemoveFromSet(t *testing.T) {
	t.Run("remove from set success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("RemoveMember", mock.Anything, fixedKey, value).Return(nil)

		storage.RemoveFromSet(keyName, value)
		mockSet.AssertExpectations(t)
	})

	t.Run("remove from set error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("RemoveMember", mock.Anything, fixedKey, value).Return(errors.New("error removing from set"))

		storage.RemoveFromSet(keyName, value)
		mockSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet

		storage.RemoveFromSet("key", "value")

		// Since storage is disconnected, no calls should be made to mockSet
		mockSet.AssertExpectations(t)
	})
}

func TestIsMemberOfSet(t *testing.T) {
	t.Run("is member of set true", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("IsMember", mock.Anything, fixedKey, value).Return(true, nil)

		isMember := storage.IsMemberOfSet(keyName, value)
		assert.True(t, isMember)
		mockSet.AssertExpectations(t)
	})

	t.Run("is member of set false", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("IsMember", mock.Anything, fixedKey, value).Return(false, nil)

		isMember := storage.IsMemberOfSet(keyName, value)
		assert.False(t, isMember)
		mockSet.AssertExpectations(t)
	})

	t.Run("error checking membership", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet
		keyName := "key"
		value := "value"
		fixedKey := storage.fixKey(keyName)
		mockSet.On("IsMember", mock.Anything, fixedKey, value).Return(false, errors.New("error checking membership"))

		isMember := storage.IsMemberOfSet(keyName, value)
		assert.False(t, isMember)
		mockSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockSet := tempmocks.NewSet(t)
		storage.setStorage = mockSet

		isMember := storage.IsMemberOfSet("key", "value")
		assert.False(t, isMember)

		// Since storage is disconnected, no calls should be made to mockSet
		mockSet.AssertExpectations(t)
	})
}

func TestAddToSortedSet(t *testing.T) {
	t.Run("add to sorted set success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		value := "value"
		score := 1.0
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("AddScoredMember", mock.Anything, fixedKey, value, score).Return(int64(1), nil)

		storage.AddToSortedSet(keyName, value, score)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("add to sorted set error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		value := "value"
		score := 1.0
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("AddScoredMember", mock.Anything, fixedKey, value, score).Return(int64(1), errors.New("error adding to sorted set"))

		storage.AddToSortedSet(keyName, value, score)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet

		storage.AddToSortedSet("key", "value", 1.0)
		// Since storage is disconnected, no calls should be made to mockSortedSet

		mockSortedSet.AssertExpectations(t)
	})
}

func TestGetSortedSetRange(t *testing.T) {
	t.Run("get sorted set range success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		scoreFrom := "-inf"
		scoreTo := "+inf"
		fixedKey := storage.fixKey(keyName)
		expectedValues := []string{"value1", "value2"}
		expectedScores := []float64{1.0, 2.0}
		mockSortedSet.On("GetMembersByScoreRange", mock.Anything, fixedKey, scoreFrom, scoreTo).Return([]interface{}{"value1", "value2"}, expectedScores, nil)

		values, scores, err := storage.GetSortedSetRange(keyName, scoreFrom, scoreTo)
		assert.NoError(t, err)
		assert.Equal(t, expectedValues, values)
		assert.Equal(t, expectedScores, scores)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("get sorted set range empty", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		scoreFrom := "-inf"
		scoreTo := "+inf"
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("GetMembersByScoreRange", mock.Anything, fixedKey, scoreFrom, scoreTo).Return([]interface{}{}, []float64{}, nil)

		values, scores, err := storage.GetSortedSetRange(keyName, scoreFrom, scoreTo)
		assert.NoError(t, err)
		assert.Empty(t, values)
		assert.Empty(t, scores)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("get sorted set range error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		scoreFrom := "-inf"
		scoreTo := "+inf"
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("GetMembersByScoreRange", mock.Anything, fixedKey, scoreFrom, scoreTo).Return(nil, nil, errors.New("error getting sorted set range"))

		values, scores, err := storage.GetSortedSetRange(keyName, scoreFrom, scoreTo)
		assert.Error(t, err)
		assert.Nil(t, values)
		assert.Nil(t, scores)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet

		values, scores, err := storage.GetSortedSetRange("key", "-inf", "+inf")
		assert.Error(t, err)
		assert.Nil(t, values)
		assert.Nil(t, scores)
		// Expect no calls to mockSortedSet since the storage is disconnected
		mockSortedSet.AssertExpectations(t)
	})
}

func TestRemoveSortedSetRange(t *testing.T) {
	t.Run("remove sorted set range success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		scoreFrom := "-inf"
		scoreTo := "+inf"
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("RemoveMembersByScoreRange", mock.Anything, fixedKey, scoreFrom, scoreTo).Return(int64(2), nil)

		err := storage.RemoveSortedSetRange(keyName, scoreFrom, scoreTo)
		assert.NoError(t, err)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("remove sorted set range error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet
		keyName := "key"
		scoreFrom := "-inf"
		scoreTo := "+inf"
		fixedKey := storage.fixKey(keyName)
		mockSortedSet.On("RemoveMembersByScoreRange", mock.Anything, fixedKey, scoreFrom, scoreTo).Return(int64(0), errors.New("error removing sorted set range"))

		err := storage.RemoveSortedSetRange(keyName, scoreFrom, scoreTo)
		assert.Error(t, err)
		mockSortedSet.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockSortedSet := tempmocks.NewSortedSet(t)
		storage.sortedSetStorage = mockSortedSet

		err := storage.RemoveSortedSetRange("key", "-inf", "+inf")
		assert.Error(t, err)
		// Expect no calls to mockSortedSet since the storage is disconnected
		mockSortedSet.AssertExpectations(t)
	})
}

func TestScanKeys(t *testing.T) {
	t.Run("scan keys success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		pattern := "prefix:*"
		expectedKeys := []string{"prefix:key1", "prefix:key2"}
		mockKv.On("Keys", mock.Anything, pattern).Return(expectedKeys, nil)

		keys, err := storage.ScanKeys(pattern)
		assert.NoError(t, err)
		assert.Equal(t, expectedKeys, keys)
		mockKv.AssertExpectations(t)
	})

	t.Run("scan keys error", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv
		pattern := "prefix:*"
		mockKv.On("Keys", mock.Anything, pattern).Return(nil, errors.New("error scanning keys"))

		keys, err := storage.ScanKeys(pattern)
		assert.Error(t, err)
		assert.Nil(t, keys)
		mockKv.AssertExpectations(t)
	})

	t.Run("storage disconnected", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		mockKv := tempmocks.NewKeyValue(t)
		storage.kvStorage = mockKv

		keys, err := storage.ScanKeys("prefix:*")
		assert.Error(t, err)
		assert.Nil(t, keys)
		mockKv.AssertExpectations(t)
	})
}

func TestGetKeyPrefix(t *testing.T) {
	t.Run("with prefix", func(t *testing.T) {
		prefix := "prefix:"
		storage := &RedisCluster{KeyPrefix: prefix}

		assert.Equal(t, prefix, storage.GetKeyPrefix())
	})
	t.Run("without prefix", func(t *testing.T) {
		prefix := ""
		storage := &RedisCluster{KeyPrefix: prefix}

		assert.Equal(t, prefix, storage.GetKeyPrefix())
	})
}

func TestStartPubSubHandler(t *testing.T) {
	t.Run("error on queue retrieval", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		err := storage.StartPubSubHandler(context.Background(), "test-channel", nil)
		assert.Error(t, err)
	})

	t.Run("context canceled", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := storage.StartPubSubHandler(ctx, "test-channel", nil)
		assert.NoError(t, err)
	})

	t.Run("message received", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockQueue := tempmocks.NewQueue(t)
		storage.queueStorage = mockQueue

		mockMsg := tempmocks.NewMessage(t)
		mockMsg.On("Payload").Return("test message", nil)

		mockedSubscription := tempmocks.NewSubscription(t)
		mockedSubscription.On("Receive", mock.Anything).Return(mockMsg, nil)
		mockedSubscription.On("Close").Return(nil).Maybe()

		mockQueue.On("Subscribe", mock.Anything, "test-channel").Return(mockedSubscription, nil)
		defer mockQueue.AssertExpectations(t)

		callbackCalled := make(chan bool, 1)
		callback := func(obj interface{}) {
			msg, ok := obj.(model.Message)
			assert.True(t, ok)

			msgPayload, err := msg.Payload()
			assert.NoError(t, err)
			payload, err := msg.Payload()
			assert.NoError(t, err)
			assert.Equal(t, payload, msgPayload)

			callbackCalled <- true
		}

		go func() {
			//nolint
			_ = storage.StartPubSubHandler(context.Background(), "test-channel", callback)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		select {
		case ok := <-callbackCalled:
			assert.True(t, ok, "callback was called")
		case <-ctx.Done():
			assert.Fail(t, "callback was not called within the timeout period")
		}
	})

	t.Run("error on receive", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockQueue := tempmocks.NewQueue(t)
		storage.queueStorage = mockQueue

		expectedErr := errors.New("test err")

		mockedSubscription := tempmocks.NewSubscription(t)
		mockedSubscription.On("Receive", mock.Anything).Return(nil, errors.New("test err"))
		mockedSubscription.On("Close").Return(nil).Maybe()

		mockQueue.On("Subscribe", mock.Anything, "test-channel").Return(mockedSubscription, nil)
		defer mockQueue.AssertExpectations(t)

		err := storage.StartPubSubHandler(context.Background(), "test-channel", nil)
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("error on receive closed network", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockQueue := tempmocks.NewQueue(t)
		storage.queueStorage = mockQueue

		expectedErr := errors.New("redis: client is closed")

		mockedSubscription := tempmocks.NewSubscription(t)
		mockedSubscription.On("Receive", mock.Anything).Return(nil, errors.New("use of closed network connection"))
		mockedSubscription.On("Close").Return(nil).Maybe()

		mockQueue.On("Subscribe", mock.Anything, "test-channel").Return(mockedSubscription, nil)
		defer mockQueue.AssertExpectations(t)

		err := storage.StartPubSubHandler(context.Background(), "test-channel", nil)
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestPublish(t *testing.T) {
	t.Run("error on queue retrieval", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		storage.ConnectionHandler.storageUp.Store(false)
		defer storage.ConnectionHandler.storageUp.Store(true)
		err := storage.Publish("test-channel", "test message")
		assert.Error(t, err)
	})

	t.Run("publish success", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockQueue := tempmocks.NewQueue(t)
		storage.queueStorage = mockQueue

		mockQueue.On("Publish", mock.Anything, "test-channel", "test message").Return(int64(1), nil)

		err := storage.Publish("test-channel", "test message")
		assert.NoError(t, err)
		mockQueue.AssertExpectations(t)
	})

	t.Run("error on publish", func(t *testing.T) {
		storage := &RedisCluster{ConnectionHandler: rc}
		mockQueue := tempmocks.NewQueue(t)
		storage.queueStorage = mockQueue

		expectedErr := errors.New("publish error")
		mockQueue.On("Publish", mock.Anything, "test-channel", "test message").Return(int64(0), expectedErr)
		defer mockQueue.AssertExpectations(t)

		err := storage.Publish("test-channel", "test message")
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}
