package rpc

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/gorpc"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
)

// purgeRPCMock is a fake MDCB answering Ping and PurgeAnalyticsData.
type purgeRPCMock struct {
	failPing   atomic.Bool
	failPurge  atomic.Bool
	purgeCalls atomic.Int32
	// failPayload makes PurgeAnalyticsData fail for payloads containing it.
	failPayload string
	// purgeDelay is how long PurgeAnalyticsData takes to answer.
	purgeDelay time.Duration
}

// loopbackListener listens on a random loopback port picked by the kernel,
// so the server does not race other tests for a port.
type loopbackListener struct {
	l net.Listener
}

func (ln *loopbackListener) Init(string) (err error) {
	ln.l, err = net.Listen("tcp", "127.0.0.1:0")
	return err
}

func (ln *loopbackListener) Accept() (net.Conn, error) { return ln.l.Accept() }

func (ln *loopbackListener) Close() error { return ln.l.Close() }

func (ln *loopbackListener) ListenAddr() net.Addr { return ln.l.Addr() }

// startPurgeRPCMock starts the fake MDCB and points the package level RPC
// client at it. The previous client state is restored on cleanup.
func startPurgeRPCMock(t *testing.T) *purgeRPCMock {
	t.Helper()

	m := &purgeRPCMock{}

	d := gorpc.NewDispatcher()
	d.AddFunc("Ping", func() (bool, error) {
		if m.failPing.Load() {
			return false, errors.New("ping failed")
		}
		return true, nil
	})
	d.AddFunc("PurgeAnalyticsData", func(data string) error {
		m.purgeCalls.Add(1)
		time.Sleep(m.purgeDelay)
		if m.failPurge.Load() {
			return errors.New("mdcb unavailable")
		}
		if m.failPayload != "" && strings.Contains(data, m.failPayload) {
			return errors.New("payload rejected")
		}
		return nil
	})

	ln := &loopbackListener{}
	server := gorpc.NewTCPServer("127.0.0.1:0", d.NewHandlerFunc())
	server.Listener = ln
	server.LogError = gorpc.NilErrorLogger
	require.NoError(t, server.Start())

	client := gorpc.NewTCPClient(ln.l.Addr().String())
	client.LogError = gorpc.NilErrorLogger
	client.Start()

	prevFuncClient := funcClientSingleton
	prevConnected := values.ClientIsConnected()
	prevTimeout := GlobalRPCCallTimeout

	funcClientSingleton = d.NewFuncClient(client)
	values.clientIsConnected.Store(true)
	GlobalRPCCallTimeout = 2 * time.Second

	t.Cleanup(func() {
		funcClientSingleton = prevFuncClient
		values.clientIsConnected.Store(prevConnected)
		GlobalRPCCallTimeout = prevTimeout
		client.Stop()
		server.Stop()
	})

	return m
}

func newPurgerTestStore(t *testing.T) *storage.RedisCluster {
	t.Helper()

	store := &storage.RedisCluster{
		KeyPrefix:         "analytics-purger-test-" + uuid.New() + "-",
		IsAnalytics:       true,
		ConnectionHandler: rc,
	}
	store.Connect()

	t.Cleanup(func() {
		for i := -1; i < 10; i++ {
			store.GetAndDeleteSet(purgerKeyName(i))
		}
	})

	return store
}

func purgerKeyName(i int) string {
	if i == -1 {
		return ANALYTICS_KEYNAME
	}
	return fmt.Sprintf("%v_%v", ANALYTICS_KEYNAME, i)
}

func encodedRecord(t *testing.T, path string) []byte {
	t.Helper()
	b, err := msgpack.Marshal(&analytics.AnalyticsRecord{Method: "GET", Path: path})
	require.NoError(t, err)
	return b
}

// storedPaths pops the records stored under key and returns their decoded paths.
func storedPaths(t *testing.T, store storage.Handler, key string) []string {
	t.Helper()
	var paths []string
	for _, v := range store.GetAndDeleteSet(key) {
		rec, err := decodeAnalyticsRecord(v)
		require.NoError(t, err)
		paths = append(paths, rec.Path)
	}
	return paths
}

// handlerOnly hides the optional AppendToSetPipelined method of the
// wrapped store, like a storage.Handler implementation without it.
type handlerOnly struct {
	storage.Handler
}

// fixedExpiry reports a fixed TTL for every key of the wrapped store.
type fixedExpiry struct {
	storage.Handler
	ttl int64
}

func (s fixedExpiry) GetExp(string) (int64, error) { return s.ttl, nil }

func TestPurgeCache_RPCFailure(t *testing.T) {
	t.Run("records are kept in redis when PurgeAnalyticsData fails", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a"), encodedRecord(t, "/b")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(1), m.purgeCalls.Load())
		assert.ElementsMatch(t, []string{"/a", "/b"}, storedPaths(t, store, ANALYTICS_KEYNAME),
			"analytics must stay in redis when the RPC call fails")
	})

	t.Run("records are delivered on the next purge once RPC recovers", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		m.failPurge.Store(false)
		purger.PurgeCache()

		assert.Equal(t, int32(2), m.purgeCalls.Load())
		assert.Empty(t, storedPaths(t, store, ANALYTICS_KEYNAME),
			"analytics must be removed from redis after a successful purge")
	})

	t.Run("restored records keep their expiry across failed cycles", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})
		require.NoError(t, store.SetExp(ANALYTICS_KEYNAME, 100))

		purger := &Purger{Store: store}
		for i := 0; i < 3; i++ {
			purger.PurgeCache()

			ttl, err := store.GetExp(ANALYTICS_KEYNAME)
			require.NoError(t, err)
			assert.Greater(t, ttl, int64(0), "restored key must keep an expiry, cycle %d", i)
			assert.LessOrEqual(t, ttl, int64(100), "expiry must not be extended, cycle %d", i)
			assert.GreaterOrEqual(t, ttl, int64(99), "expiry must not drift earlier, cycle %d", i)
		}
		assert.Equal(t, int32(3), m.purgeCalls.Load())
	})

	t.Run("time spent on a slow failing call counts against the expiry", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)
		m.purgeDelay = 1100 * time.Millisecond

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})
		require.NoError(t, store.SetExp(ANALYTICS_KEYNAME, 10))

		purger := &Purger{Store: store}
		purger.PurgeCache()

		ttl, err := store.GetExp(ANALYTICS_KEYNAME)
		require.NoError(t, err)
		assert.Greater(t, ttl, int64(0), "restored key must keep an expiry")
		assert.LessOrEqual(t, ttl, int64(9), "expiry must not be reset to its value before the call")
		assert.Equal(t, []string{"/a"}, storedPaths(t, store, ANALYTICS_KEYNAME))
	})

	t.Run("records that expire during the failed call are not restored", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})

		// Redis reports TTL 0 when less than half a second is left.
		purger := &Purger{Store: fixedExpiry{Handler: store, ttl: 0}}
		purger.PurgeCache()

		assert.Equal(t, int32(1), m.purgeCalls.Load())
		assert.Empty(t, storedPaths(t, store, ANALYTICS_KEYNAME))
	})

	t.Run("records without expiry are restored without expiry", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		ttl, err := store.GetExp(ANALYTICS_KEYNAME)
		require.NoError(t, err)
		assert.Equal(t, int64(-1), ttl)
		assert.Equal(t, []string{"/a"}, storedPaths(t, store, ANALYTICS_KEYNAME))
	})

	t.Run("a rejected key does not block the other keys", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPayload = "/rejected"

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(purgerKeyName(-1), [][]byte{encodedRecord(t, "/rejected")})
		store.AppendToSetPipelined(purgerKeyName(3), [][]byte{encodedRecord(t, "/ok")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(2), m.purgeCalls.Load())
		assert.Equal(t, []string{"/rejected"}, storedPaths(t, store, purgerKeyName(-1)))
		assert.Empty(t, storedPaths(t, store, purgerKeyName(3)))
	})

	t.Run("undecodable records are restored byte for byte", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		valid := encodedRecord(t, "/a")
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{valid, []byte("not-msgpack")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(1), m.purgeCalls.Load())
		assert.ElementsMatch(t, []interface{}{string(valid), "not-msgpack"}, store.GetAndDeleteSet(ANALYTICS_KEYNAME))
	})

	t.Run("store without pipelined append falls back to AppendToSet", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPurge.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a"), encodedRecord(t, "/b")})

		purger := &Purger{Store: handlerOnly{store}}
		purger.PurgeCache()

		assert.Equal(t, int32(1), m.purgeCalls.Load())
		assert.ElementsMatch(t, []string{"/a", "/b"}, storedPaths(t, store, ANALYTICS_KEYNAME))
	})

	t.Run("successful purge sends every key and empties redis", func(t *testing.T) {
		m := startPurgeRPCMock(t)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(purgerKeyName(-1), [][]byte{encodedRecord(t, "/legacy")})
		store.AppendToSetPipelined(purgerKeyName(3), [][]byte{encodedRecord(t, "/multi")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(2), m.purgeCalls.Load())
		assert.Empty(t, storedPaths(t, store, purgerKeyName(-1)))
		assert.Empty(t, storedPaths(t, store, purgerKeyName(3)))
	})

	t.Run("nothing is popped when ping fails", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		m.failPing.Store(true)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(0), m.purgeCalls.Load())
		assert.Equal(t, []string{"/a"}, storedPaths(t, store, ANALYTICS_KEYNAME))
	})

	t.Run("nothing is popped when the RPC client is disconnected", func(t *testing.T) {
		m := startPurgeRPCMock(t)
		values.clientIsConnected.Store(false)

		store := newPurgerTestStore(t)
		store.AppendToSetPipelined(ANALYTICS_KEYNAME, [][]byte{encodedRecord(t, "/a")})

		purger := &Purger{Store: store}
		purger.PurgeCache()

		assert.Equal(t, int32(0), m.purgeCalls.Load())
		assert.Equal(t, []string{"/a"}, storedPaths(t, store, ANALYTICS_KEYNAME))
	})
}
