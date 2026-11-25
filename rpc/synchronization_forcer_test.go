package rpc

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

var rc *storage.ConnectionHandler

func TestMain(m *testing.M) {
	conf, err := config.New()
	if err != nil {
		panic(err)
	}

	rc = storage.NewConnectionHandler(context.Background())
	go rc.Connect(context.Background(), nil, conf)

	timeout, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}

	os.Exit(m.Run())
}

func TestNewSyncForcer(t *testing.T) {
	sf := NewSyncForcer(rc, func() []byte { return []byte{} })

	assert.True(t, sf.store.ControllerInitiated())
	assert.Equal(t, "synchronizer-group-", sf.store.KeyPrefix)

	assert.Equal(t, true, sf.store.ConnectionHandler.Connected())
}

func TestGroupLoginCallback(t *testing.T) {
	sf := NewSyncForcer(rc, func() []byte { return []byte{} })
	defer sf.store.DeleteAllKeys()

	key := "key"
	groupID := "group"

	//first time, it should force since the group key doesn't exists
	groupLogin, ok := sf.GroupLoginCallback(key, groupID).(apidef.GroupLoginRequest)
	assert.True(t, ok)
	assert.Equal(t, true, groupLogin.ForceSync)
	assert.Equal(t, key, groupLogin.UserKey)
	assert.Equal(t, groupID, groupLogin.GroupID)

	//second time, it shouldn't force since the group key already exists
	groupLogin, ok = sf.GroupLoginCallback(key, groupID).(apidef.GroupLoginRequest)
	assert.True(t, ok)
	assert.Equal(t, false, groupLogin.ForceSync)
	assert.Equal(t, key, groupLogin.UserKey)
	assert.Equal(t, groupID, groupLogin.GroupID)
}

func TestGetNodeDataFunc(t *testing.T) {
	// Checking if the getNodeDataFunc is returning different values on each call
	valueToFetch := "foo"
	sf := NewSyncForcer(rc, func() []byte { return []byte(valueToFetch) })
	assert.Equal(t, valueToFetch, string(sf.getNodeDataFunc()))

	valueToFetch = "bar"
	assert.Equal(t, valueToFetch, string(sf.getNodeDataFunc()))
}

// newTestSyncForcer returns a sync forcer that is not the process singleton, so
// a test can simulate several gateways of the same group sharing one Redis.
// Calling it again in a test simulates a restart of a gateway: the in-memory
// state is gone, the shared storage is kept.
func newTestSyncForcer(t *testing.T) *SyncronizerForcer {
	t.Helper()

	sf := &SyncronizerForcer{
		store:           &storage.RedisCluster{KeyPrefix: syncForcerKeyPrefix, ConnectionHandler: rc},
		getNodeDataFunc: func() []byte { return []byte{} },
	}
	sf.store.Connect()
	t.Cleanup(func() { sf.store.DeleteAllKeys() })

	return sf
}

// loginForceSync builds the group login request of sf and reports whether it
// asks MDCB for a forced synchronisation. The login result is not reported.
func loginForceSync(t *testing.T, sf *SyncronizerForcer, groupID string) bool {
	t.Helper()

	req, ok := sf.GroupLoginCallback("key", groupID).(apidef.GroupLoginRequest)
	assert.True(t, ok)
	assert.Equal(t, groupID, req.GroupID)

	return req.ForceSync
}

// connect performs a successful group login of sf, like rpc.groupLogin does,
// and reports whether it forced a synchronisation.
func connect(t *testing.T, sf *SyncronizerForcer, groupID string) bool {
	t.Helper()

	forced := loginForceSync(t, sf, groupID)
	sf.groupLoginResult(true)

	return forced
}

func resyncNeeded(t *testing.T, sf *SyncronizerForcer, groupID string) bool {
	t.Helper()

	needed, err := sf.isResyncNeeded(groupID)
	assert.NoError(t, err)

	return needed
}

// syncedGroup returns n gateways of a group whose storage is synchronised.
func syncedGroup(t *testing.T, groupID string, n int) []*SyncronizerForcer {
	t.Helper()

	gws := make([]*SyncronizerForcer, n)
	for i := range gws {
		gws[i] = newTestSyncForcer(t)
		assert.Equal(t, i == 0, connect(t, gws[i], groupID), "only the first gateway of the group forces")
	}

	return gws
}

// TT-15569: a gateway joining a group whose storage is already synchronised
// must not force MDCB to resynchronise all keys.
func TestGroupLoginCallback_NewGatewayInSyncedGroupDoesNotForce(t *testing.T) {
	groupID := "group-scale-up"

	first := newTestSyncForcer(t)
	assert.True(t, connect(t, first, groupID), "first gateway of the group must force")

	for i := 0; i < 4; i++ {
		joining := newTestSyncForcer(t)
		assert.False(t, connect(t, joining, groupID), "joining gateway must not force")
	}
}

func TestGroupLoginCallback_ResyncIsForcedOncePerGroup(t *testing.T) {
	groupID := "group-reconnect"
	gws := syncedGroup(t, groupID, 3)

	// MDCB connection lost on every gateway of the group
	for _, gw := range gws {
		gw.RequestResync()
	}
	assert.True(t, resyncNeeded(t, gws[0], groupID), "request must be recorded for the group")

	assert.True(t, connect(t, gws[0], groupID), "lock winner must force")
	assert.False(t, connect(t, gws[1], groupID))
	assert.False(t, connect(t, gws[2], groupID))

	for _, gw := range gws {
		assert.False(t, gw.IsResyncRequested(), "request must be consumed")
	}
	assert.False(t, resyncNeeded(t, gws[0], groupID), "record must be removed once served")

	// without a new request nobody forces again
	assert.False(t, connect(t, gws[0], groupID))
}

// TT-12417: the gateways restart while the resync is pending (e.g. crash loop
// during the MDCB outage). The request must survive in the shared storage.
func TestGroupLoginCallback_ResyncSurvivesRestart(t *testing.T) {
	groupID := "group-restart"
	gws := syncedGroup(t, groupID, 2)

	gws[0].RequestResync()
	gws[1].RequestResync()

	ttl, err := gws[0].store.GetKeyTTL(groupID + resyncNeededSuffix)
	assert.NoError(t, err)
	assert.Equal(t, int64(-1), ttl, "the record must not expire")

	gws[0] = newTestSyncForcer(t) // restart
	assert.True(t, connect(t, gws[0], groupID), "restarted gateway must force the recorded resync")

	gws[1] = newTestSyncForcer(t) // restart
	assert.False(t, connect(t, gws[1], groupID), "the resync was already forced")
	assert.False(t, resyncNeeded(t, gws[1], groupID))
}

// TT-12417: the gateway holding the resync lock dies before its forced login
// completes. Another gateway must force once the lock expires.
func TestGroupLoginCallback_LockHolderDiesBeforeResult(t *testing.T) {
	prevTTL := resyncLockTTL
	resyncLockTTL = 200 * time.Millisecond
	t.Cleanup(func() { resyncLockTTL = prevTTL })

	groupID := "group-lock-holder-dies"
	gws := syncedGroup(t, groupID, 3)
	for _, gw := range gws {
		gw.RequestResync()
	}

	assert.True(t, loginForceSync(t, gws[0], groupID), "lock winner must force")
	// gws[0] dies here: its login result is never reported

	assert.False(t, connect(t, gws[1], groupID), "lock is held by gws[0]")
	assert.False(t, gws[1].IsResyncRequested())
	assert.True(t, resyncNeeded(t, gws[1], groupID), "record must be kept until a forced login succeeds")

	time.Sleep(2 * resyncLockTTL)

	assert.True(t, connect(t, gws[2], groupID), "the recorded resync must be forced once the lock expired")
	assert.False(t, resyncNeeded(t, gws[2], groupID))
	assert.False(t, connect(t, gws[1], groupID))
}

// TT-12417: the forced login doesn't reach MDCB. The request must be kept for
// the group, also when the gateway restarts.
func TestGroupLoginCallback_FailedForcedLoginKeepsRequest(t *testing.T) {
	groupID := "group-failed-login"
	gws := syncedGroup(t, groupID, 2)

	gws[0].RequestResync()
	assert.True(t, loginForceSync(t, gws[0], groupID))
	gws[0].groupLoginResult(false)

	assert.True(t, gws[0].IsResyncRequested(), "failed login must re-arm the request")
	assert.True(t, resyncNeeded(t, gws[0], groupID), "failed login must keep the record")

	gws[0] = newTestSyncForcer(t) // restart
	assert.True(t, connect(t, gws[0], groupID), "lock must be released after the failed login")
	assert.False(t, connect(t, gws[1], groupID))
}

func TestGroupLoginCallback_FailedForcedLoginTakenOverByGroup(t *testing.T) {
	groupID := "group-failed-login-takeover"
	gws := syncedGroup(t, groupID, 2)

	gws[0].RequestResync()
	assert.True(t, loginForceSync(t, gws[0], groupID))
	gws[0].groupLoginResult(false)

	// gws[1] has no request of its own, the group record is enough
	assert.True(t, connect(t, gws[1], groupID))
	assert.False(t, connect(t, gws[0], groupID), "gws[1] already resynchronised the group")
	assert.False(t, gws[0].IsResyncRequested())
}

// TT-12417: MDCB crashes again right after a successful forced resync (within
// the lock TTL). The new outage must be resynchronised again.
func TestGroupLoginCallback_NewOutageAfterResync(t *testing.T) {
	groupID := "group-new-outage"
	gws := syncedGroup(t, groupID, 2)

	gws[0].RequestResync()
	gws[1].RequestResync()
	assert.True(t, connect(t, gws[0], groupID))
	assert.False(t, connect(t, gws[1], groupID))

	// second outage
	gws[0].RequestResync()
	gws[1].RequestResync()
	assert.True(t, resyncNeeded(t, gws[0], groupID))
	assert.True(t, connect(t, gws[1], groupID), "a new outage must force again")
	assert.False(t, connect(t, gws[0], groupID))
}

// A gateway that reconnects later than the others after the same outage keeps
// reporting the connection loss after the group was already resynchronised. It
// must not record a new resync.
func TestGroupLoginCallback_LateReconnectFromSameOutageDoesNotForce(t *testing.T) {
	groupID := "group-late-reconnect"
	gws := syncedGroup(t, groupID, 2)

	gws[0].RequestResync()
	gws[1].RequestResync()
	assert.True(t, connect(t, gws[0], groupID))

	// gws[1] is still disconnected and reports the outage again
	gws[1].RequestResync()
	assert.False(t, resyncNeeded(t, gws[1], groupID), "outage already served, nothing to record")
	assert.False(t, gws[1].IsResyncRequested())
	assert.False(t, connect(t, gws[1], groupID))
}

// A request made before the first login (group unknown) is recorded and forced
// on the first login.
func TestGroupLoginCallback_RequestBeforeFirstLogin(t *testing.T) {
	groupID := "group-request-before-login"
	syncedGroup(t, groupID, 1)

	gw := newTestSyncForcer(t)
	gw.RequestResync()
	assert.False(t, resyncNeeded(t, gw, groupID), "group not known yet")

	assert.True(t, connect(t, gw, groupID))
	assert.False(t, resyncNeeded(t, gw, groupID))
}

// A full synchronisation of a fresh (flushed) storage also serves an
// outstanding resync request.
func TestGroupLoginCallback_FreshStorageServesResync(t *testing.T) {
	groupID := "group-fresh-storage"
	gws := syncedGroup(t, groupID, 1)

	gws[0].RequestResync()
	gws[0].store.DeleteKey(groupID) // group key lost

	other := newTestSyncForcer(t)
	assert.True(t, connect(t, other, groupID))
	assert.False(t, resyncNeeded(t, other, groupID))
	assert.False(t, connect(t, gws[0], groupID), "the outage was served by the full synchronisation")
}

func TestSetFirstConnection_BackwardCompatible(t *testing.T) {
	groupID := "group-deprecated-api"

	sf := newTestSyncForcer(t)
	assert.True(t, connect(t, sf, groupID))

	sf.SetFirstConnection(true)
	assert.True(t, sf.GetIsFirstConnection())
	assert.True(t, connect(t, sf, groupID))
	assert.False(t, sf.GetIsFirstConnection())

	// false cancels the request of this gateway, the group record is kept
	sf.SetFirstConnection(true)
	sf.SetFirstConnection(false)
	assert.False(t, sf.GetIsFirstConnection())
	assert.True(t, resyncNeeded(t, sf, groupID))
}

func TestSyncForcer_ConcurrentAccess(t *testing.T) {
	groupID := "group-concurrent"
	sf := newTestSyncForcer(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			sf.RequestResync()
		}()
		go func(i int) {
			defer wg.Done()
			sf.GroupLoginCallback("key", groupID)
			sf.groupLoginResult(i%2 == 0)
		}(i)
	}
	wg.Wait()
}
