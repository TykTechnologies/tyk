package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/gorpc"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const keyspaceTestOrg = "default"

// spySessionManager counts the key writes and removals of the gateway.
type spySessionManager struct {
	SessionHandler
	updated atomic.Int32
	removed atomic.Int32
}

func (s *spySessionManager) UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error {
	s.updated.Add(1)
	return s.SessionHandler.UpdateSession(keyName, session, resetTTLTo, hashed)
}

func (s *spySessionManager) RemoveSession(orgID string, keyName string, hashed bool) bool {
	s.removed.Add(1)
	return s.SessionHandler.RemoveSession(orgID, keyName, hashed)
}

// keyspaceMaster is a mock MDCB serving the control plane keys.
type keyspaceMaster struct {
	mu   sync.Mutex
	keys map[string]string
	gets int
}

func (m *keyspaceMaster) set(keyName string, session *user.SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[keyName] = jsonMarshalString(session)
}

func (m *keyspaceMaster) resetCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = 0
}

func (m *keyspaceMaster) getCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gets
}

func (m *keyspaceMaster) getKey(_ string, keyName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if session, ok := m.keys[keyName]; ok {
		return session, nil
	}
	// what MDCB returns for a key that doesn't exist on the control plane
	return "", errors.New("Key not found")
}

type keyspaceTest struct {
	ts       *Test
	master   *keyspaceMaster
	spy      *spySessionManager
	listener RPCStorageHandler
	hashKeys bool
}

// newKeyspaceTest starts a gateway with the synchroniser and the RPC cache enabled
// and connects its RPC client to a mock MDCB.
//
// The gateway is started in local mode and the RPC client is connected afterwards:
// the RPC client always starts in emergency mode and leaving it queues a reload,
// which blocks while StartTest is still logging in synchronously because the
// reload loop isn't running yet.
func newKeyspaceTest(t *testing.T, hashKeys bool) *keyspaceTest {
	t.Helper()

	prevSyncLogin := rpc.UseSyncLoginRPC
	rpc.UseSyncLoginRPC = true

	master := &keyspaceMaster{keys: map[string]string{}}
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetKey", master.getKey)

	rpcMock, connectionString := startRPCMock(dispatcher)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.SlaveOptions.RPCKey = "test_org"
		globalConf.SlaveOptions.APIKey = "test"
		globalConf.SlaveOptions.CallTimeout = 1
		globalConf.SlaveOptions.RPCPoolSize = 2
		globalConf.SlaveOptions.ConnectionString = connectionString
		globalConf.SlaveOptions.EnableRPCCache = true
		globalConf.SlaveOptions.SynchroniserEnabled = true
		globalConf.HashKeys = hashKeys
	})

	spy := &spySessionManager{SessionHandler: ts.Gw.GlobalSessionManager}
	ts.Gw.GlobalSessionManager = spy

	t.Cleanup(func() {
		ts.Gw.GlobalSessionManager = spy.SessionHandler
		ts.Close()
		stopRPCMock(rpcMock)
		rpc.ResetEmergencyMode()
		rpc.UseSyncLoginRPC = prevSyncLogin
	})

	listener := RPCStorageHandler{
		KeyPrefix:        "rpc.listener.",
		SuppressRegister: true,
		HashKeys:         hashKeys,
		Gw:               ts.Gw,
	}
	require.True(t, listener.Connect())
	require.Eventually(t, func() bool {
		if rpc.IsEmergencyMode() {
			return false
		}
		_, err := rpc.FuncClientSingleton("GetKey", "keyspace-test-probe")
		return isMasterAnswer(err)
	}, 10*time.Second, 50*time.Millisecond, "mock MDCB must be reachable")
	master.resetCount()

	return &keyspaceTest{
		ts:       ts,
		master:   master,
		spy:      spy,
		listener: listener,
		hashKeys: hashKeys,
	}
}

// newKey returns the keyspace event and the hash of a new key. When local is set,
// the key is stored in the data plane Redis like the synchroniser does.
func (k *keyspaceTest) newKey(t *testing.T, name string, local *user.SessionState) (event, keyHash string) {
	t.Helper()

	key := k.ts.Gw.generateToken(keyspaceTestOrg, name)
	keyHash = storage.HashKey(key, k.hashKeys)

	event = key
	if k.hashKeys {
		event = keyHash + ":hashed"
	}

	if local != nil {
		require.NoError(t, k.spy.SessionHandler.UpdateSession(keyHash, local, 0, k.hashKeys))
	}

	return event, keyHash
}

func (k *keyspaceTest) localSession(t *testing.T, keyHash string) (*user.SessionState, bool) {
	t.Helper()

	store := k.ts.Gw.GlobalSessionManager.Store()
	raw, err := store.GetRawKey(store.GetKeyPrefix() + keyHash)
	if err != nil {
		return nil, false
	}

	session := &user.SessionState{}
	require.NoError(t, json.Unmarshal([]byte(raw), session))

	return session, true
}

func (k *keyspaceTest) process(events ...string) {
	k.listener.ProcessKeySpaceChanges(events, keyspaceTestOrg)
}

func keyspaceSession(tags ...string) *user.SessionState {
	session := CreateStandardSession()
	session.OrgID = keyspaceTestOrg
	session.Tags = tags
	// CreateStandardSession uses the current time, fixed values keep sessions comparable
	session.LastCheck = 1700000000
	session.QuotaRenews = 1700000020
	return session
}

func forEachHashKeys(t *testing.T, fn func(t *testing.T, hashKeys bool)) {
	t.Helper()

	for _, hashKeys := range []bool{true, false} {
		t.Run(fmt.Sprintf("hash_keys=%v", hashKeys), func(t *testing.T) {
			fn(t, hashKeys)
		})
	}
}

// TT-15569: a resynchronisation must not rewrite keys that didn't change.
func TestProcessKeySpaceChanges_UnchangedKeyIsNotRewritten(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		local := keyspaceSession("a")
		local.LastUpdated = "1"
		event, keyHash := k.newKey(t, "unchanged", local)

		remote := keyspaceSession("a")
		remote.LastUpdated = "2" // ignored in the comparison
		k.master.set("apikey-"+keyHash, remote)

		k.process(event)

		assert.Zero(t, k.spy.removed.Load(), "key must not be removed")
		assert.Zero(t, k.spy.updated.Load(), "unchanged key must not be written")
		assert.Equal(t, 1, k.master.getCount())

		session, found := k.localSession(t, keyHash)
		require.True(t, found)
		assert.Equal(t, "1", session.LastUpdated, "stored key must be untouched")
	})
}

// TT-15569: a changed key is overwritten, never removed first, so it's never missing.
func TestProcessKeySpaceChanges_ChangedKeyIsUpdatedInPlace(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		event, keyHash := k.newKey(t, "changed", keyspaceSession("old"))
		k.master.set("apikey-"+keyHash, keyspaceSession("new"))

		k.process(event)

		assert.Zero(t, k.spy.removed.Load(), "key must not be removed")
		assert.Equal(t, int32(1), k.spy.updated.Load())

		session, found := k.localSession(t, keyHash)
		require.True(t, found)
		assert.Equal(t, []string{"new"}, session.Tags)
	})
}

func TestProcessKeySpaceChanges_KeyRemovedOnControlPlaneIsDeleted(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		event, keyHash := k.newKey(t, "removed", keyspaceSession("a"))

		k.process(event)

		assert.NotZero(t, k.spy.removed.Load())
		_, found := k.localSession(t, keyHash)
		assert.False(t, found, "key removed on the control plane must be removed locally")
	})
}

func TestProcessKeySpaceChanges_NewKeyIsCreated(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		event, keyHash := k.newKey(t, "new", nil)
		k.master.set("apikey-"+keyHash, keyspaceSession("a"))

		k.process(event)

		assert.Zero(t, k.spy.removed.Load())
		session, found := k.localSession(t, keyHash)
		require.True(t, found, "key must be pulled from the control plane")
		assert.Equal(t, []string{"a"}, session.Tags)
	})
}

// A value cached by the RPC layer may predate the change being processed and must
// not be written to the data plane Redis.
func TestProcessKeySpaceChanges_StaleRPCCacheIsNotUsed(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		for _, storedLocally := range []bool{true, false} {
			t.Run(fmt.Sprintf("stored locally=%v", storedLocally), func(t *testing.T) {
				k := newKeyspaceTest(t, hashKeys)

				var local *user.SessionState
				if storedLocally {
					local = keyspaceSession("old")
				}
				event, keyHash := k.newKey(t, "cached-"+fmt.Sprint(storedLocally), local)

				k.ts.Gw.RPCGlobalCache.Set("apikey-"+keyHash, jsonMarshalString(keyspaceSession("stale")), -1)
				t.Cleanup(func() { k.ts.Gw.RPCGlobalCache.Delete("apikey-" + keyHash) })
				k.master.set("apikey-"+keyHash, keyspaceSession("new"))

				k.process(event)

				session, found := k.localSession(t, keyHash)
				require.True(t, found)
				assert.Equal(t, []string{"new"}, session.Tags)
			})
		}
	})
}

// TT-12417: when MDCB can't be reached the key is handled as before (removed, as it
// may have been removed on the control plane) and a group resync is requested, which
// restores the keys still on the control plane.
func TestProcessKeySpaceChanges_MasterUnavailableRequestsResync(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		forcer := rpc.NewSyncForcer(k.ts.Gw.StorageConnectionHandler, k.listener.buildNodeInfo)
		forcer.SetFirstConnection(false)
		t.Cleanup(func() { forcer.SetFirstConnection(false) })

		event, keyHash := k.newKey(t, "unavailable", keyspaceSession("a"))
		k.master.set("apikey-"+keyHash, keyspaceSession("a"))

		rpc.SetEmergencyMode(t, true)
		t.Cleanup(func() { rpc.SetEmergencyMode(t, false) })

		k.process(event)

		_, found := k.localSession(t, keyHash)
		assert.False(t, found, "key that can't be checked is removed as before")
		assert.True(t, forcer.IsResyncRequested(), "a group resync must be requested")
	})
}

// TT-15569: a forced resynchronisation of keys that didn't change causes no writes,
// no removals and no cache flush notification.
func TestProcessKeySpaceChanges_ResyncOfSyncedGroupWritesNothing(t *testing.T) {
	forEachHashKeys(t, func(t *testing.T, hashKeys bool) {
		k := newKeyspaceTest(t, hashKeys)

		events := make([]string, 0, 20)
		for i := 0; i < 20; i++ {
			event, keyHash := k.newKey(t, fmt.Sprintf("resync-%d", i), keyspaceSession("a"))
			k.master.set("apikey-"+keyHash, keyspaceSession("a"))
			events = append(events, event)
		}

		k.process(events...)

		assert.Zero(t, k.spy.removed.Load(), "no key may be removed")
		assert.Zero(t, k.spy.updated.Load(), "no key may be written")
		assert.Equal(t, len(events), k.master.getCount(), "each key is checked once")
	})
}

func TestKeyspaceNotificationPayload(t *testing.T) {
	keys := []string{"a:hashed", "b", "cert1:CertificateAdded", "c:hashed"}

	assert.Equal(t, "a:hashed,b,cert1:CertificateAdded,c:hashed", keyspaceNotificationPayload(keys, nil))
	assert.Equal(t, "b,cert1:CertificateAdded", keyspaceNotificationPayload(keys, map[string]bool{"a:hashed": true, "c:hashed": true}))
	assert.Equal(t, "", keyspaceNotificationPayload([]string{"a:hashed"}, map[string]bool{"a:hashed": true}))
}

func TestSessionsEqual(t *testing.T) {
	remote := keyspaceSession("a")
	remote.LastUpdated = "2"

	local := keyspaceSession("a")
	local.LastUpdated = "1"
	assert.True(t, sessionsEqual(jsonMarshalString(local), remote), "LastUpdated must be ignored")

	local.Tags = []string{"b"}
	assert.False(t, sessionsEqual(jsonMarshalString(local), remote))

	assert.False(t, sessionsEqual("not json", remote))
}

// wrappedError wraps an error without calling its Error method (a gorpc.ClientError
// built in a test has no message).
type wrappedError struct{ err error }

func (e wrappedError) Error() string { return "wrapped" }
func (e wrappedError) Unwrap() error { return e.err }

func TestIsMasterAnswer(t *testing.T) {
	assert.True(t, isMasterAnswer(&gorpc.ClientError{Server: true}))
	assert.True(t, isMasterAnswer(wrappedError{&gorpc.ClientError{Server: true}}))
	assert.False(t, isMasterAnswer(&gorpc.ClientError{Timeout: true}))
	assert.False(t, isMasterAnswer(&gorpc.ClientError{Connection: true}))
	assert.False(t, isMasterAnswer(rpc.ErrRPCIsDown))
	assert.False(t, isMasterAnswer(nil))
}
