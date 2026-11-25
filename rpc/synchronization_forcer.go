package rpc

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	syncForcerKeyPrefix = "synchronizer-group-"
	// resyncLockSuffix is appended to the group key to elect the one gateway of
	// the group that forces a synchronisation after the connection to MDCB was
	// lost.
	resyncLockSuffix = ":resync-lock"
	// resyncNeededSuffix is appended to the group key to record in the shared
	// data plane Redis that the group must be resynchronised (TT-12417). The
	// record has no expiry, survives gateway restarts and is removed only once
	// a gateway of the group logged in to MDCB with ForceSync.
	resyncNeededSuffix = ":resync-needed"
	// resyncGenSuffix is appended to the group key for a counter of forced
	// synchronisations that reached MDCB. A gateway compares it with the value
	// it saw when it lost the connection to MDCB, to tell whether its outage
	// was already served by another gateway of the group.
	resyncGenSuffix = ":resync-gen"
)

// groupLoginAttempts is the number of LoginWithGroup calls a single group
// login may make (doGroupLogin: the first call and 3 retries).
const groupLoginAttempts = 4

// resyncLockTTL overrides the lifetime of the group resync lock in tests.
var resyncLockTTL time.Duration

// lockTTL is the lifetime of the group resync lock. The lock is never deleted,
// only expires, so a gateway can't remove a lock another gateway holds. It
// outlives the longest group login, so it can't expire while its holder is
// still waiting for MDCB. A lock that is never released (the holder died or
// its forced login failed) delays the next forced synchronisation by at most
// this long.
func lockTTL() time.Duration {
	if resyncLockTTL > 0 {
		return resyncLockTTL
	}

	ttl := groupLoginAttempts*GlobalRPCCallTimeout + 10*time.Second
	if ttl < time.Minute {
		ttl = time.Minute
	}

	return ttl
}

type SyncronizerForcer struct {
	store           *storage.RedisCluster
	getNodeDataFunc func() []byte

	mu sync.Mutex
	// groupID is the group of the last login. Resync requests are recorded
	// for it in the shared storage.
	groupID string
	// resyncRequested is set when this gateway lost the connection to MDCB
	// and wants a forced synchronisation on its next login.
	resyncRequested bool
	// resyncUnrecorded is set when resyncRequested couldn't be recorded in
	// the shared storage; it is recorded on the next login.
	resyncUnrecorded bool
	// inOutage is set from the first resync request after this gateway lost
	// the connection to MDCB until its next successful login.
	inOutage bool
	// outageGen is the group resync generation seen when the outage started.
	// A higher generation means the group was resynchronised since then.
	outageGen int64
	// pending is the login request built with ForceSync, until its result is
	// reported through groupLoginResult.
	pending *forcedLogin
	// heldLock is the group resync lock this gateway acquired and still holds
	// until heldUntil. It lets this gateway force again, e.g. after its forced
	// login failed, while no other gateway can.
	heldLock  string
	heldUntil time.Time
}

type forcedLogin struct {
	groupID string
}

var (
	syncForcerInstance *SyncronizerForcer
	syncForcerOnce     sync.Once
)

// NewSyncForcer returns a new syncforcer with a connected redis with a key prefix synchronizer-group- for group synchronization control.
func NewSyncForcer(controller *storage.ConnectionHandler, getNodeDataFunc func() []byte) *SyncronizerForcer {
	syncForcerOnce.Do(func() {
		sf := &SyncronizerForcer{}
		sf.store = &storage.RedisCluster{KeyPrefix: syncForcerKeyPrefix, ConnectionHandler: controller}
		sf.store.Connect()
		sf.getNodeDataFunc = getNodeDataFunc

		syncForcerInstance = sf
	})

	if syncForcerInstance != nil {
		syncForcerInstance.mu.Lock()
		syncForcerInstance.getNodeDataFunc = getNodeDataFunc
		syncForcerInstance.mu.Unlock()
	}

	return syncForcerInstance
}

// RequestResync asks for a forced synchronisation after the connection to
// MDCB was lost. The request is recorded in the shared data plane storage, so
// it survives a restart of this gateway and can be served by any gateway of
// the group. Only one gateway of the group forces it, see GroupLoginCallback.
// Requests made before the first group login are ignored.
func (sf *SyncronizerForcer) RequestResync() {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.requestResyncLocked()
}

// IsResyncRequested reports whether this gateway requested a forced
// synchronisation that it has not sent to MDCB yet.
func (sf *SyncronizerForcer) IsResyncRequested() bool {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	return sf.resyncRequested
}

// SetFirstConnection is kept for backward compatibility.
//
// Deprecated: use RequestResync. Since 5.7.0 a freshly started gateway forced
// a full synchronisation regardless of the shared group state, which caused
// a Redis surge on scale-up (TT-15569). Startup is now governed by the shared
// group state only, so SetFirstConnection(true) behaves like RequestResync and
// SetFirstConnection(false) cancels the request of this gateway and its outage
// tracking. A request already recorded for the group in the shared storage is
// kept.
func (sf *SyncronizerForcer) SetFirstConnection(isFirstConnection bool) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if isFirstConnection {
		sf.requestResyncLocked()
		return
	}

	sf.resyncRequested = false
	sf.resyncUnrecorded = false
	sf.inOutage = false
}

// GetIsFirstConnection is kept for backward compatibility.
//
// Deprecated: use IsResyncRequested.
func (sf *SyncronizerForcer) GetIsFirstConnection() bool {
	return sf.IsResyncRequested()
}

// GroupLoginCallback builds the group login request and decides whether MDCB
// should force a synchronisation. The decision is taken for the whole group
// through the shared data plane Redis, not per gateway process:
//
//   - if the group key doesn't exist in the storage (fresh or flushed data
//     plane Redis) it is created and ForceSync is set to true;
//   - if a resync is needed for the group (recorded by any gateway of the
//     group, or requested by this one), ForceSync is set to true only for the
//     gateway that acquires the group resync lock.
//
// A gateway joining a group whose storage is already synchronised does not
// force a synchronisation.
func (sf *SyncronizerForcer) GroupLoginCallback(userKey string, groupID string) interface{} {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	sf.groupID = groupID

	// a previous attempt never reported its result; its lock, if any, expires
	sf.pending = nil

	shouldForce := false
	login := &forcedLogin{groupID: groupID}

	_, err := sf.store.GetKey(groupID)
	if err != nil && errors.Is(err, storage.ErrKeyNotFound) {
		// a full synchronisation also serves an outstanding resync request
		shouldForce = true

		err = sf.store.SetKey(groupID, "", 0)
		if err != nil {
			Log.Error("error setting syncforcer key", err)
		}
		Log.Info("Forcing MDCB synchronization for group:", groupID)
	} else {
		shouldForce = sf.electResyncLocked(login)
	}

	if shouldForce {
		sf.resyncRequested = false
		sf.resyncUnrecorded = false
		sf.pending = login
	}

	return apidef.GroupLoginRequest{
		UserKey:   userKey,
		GroupID:   groupID,
		Node:      sf.getNodeDataFunc(),
		ForceSync: shouldForce,
	}
}

// electResyncLocked reports whether this gateway should force a resync of a
// group whose storage was synchronised before. It holds the group resync lock
// for the login when it does.
func (sf *SyncronizerForcer) electResyncLocked(login *forcedLogin) bool {
	needed, err := sf.isResyncNeeded(login.groupID)
	if err != nil {
		// can't coordinate with the group, keep any request for the next login
		Log.WithError(err).Error("error reading syncforcer resync request")
		return false
	}

	if sf.resyncRequested && sf.outageServedLocked(login.groupID) {
		// another gateway of the group forced a synchronisation after this
		// gateway lost the connection to MDCB
		sf.resyncRequested = false
		sf.resyncUnrecorded = false
		Log.Info("MDCB synchronization already forced for group, skipping:", login.groupID)
	}

	if !needed {
		if !sf.resyncRequested {
			return false
		}

		if !sf.resyncUnrecorded {
			// the recorded request is gone: it was served
			sf.resyncRequested = false
			return false
		}

		// the request couldn't be recorded when it was made, record it now
		if !sf.markResyncNeeded(login.groupID) {
			return false
		}
		sf.resyncUnrecorded = false
	}

	gen, err := sf.resyncGeneration(login.groupID)
	if err != nil {
		Log.WithError(err).Error("error reading syncforcer resync generation")
		return false
	}

	// one lock per resync generation: once a forced synchronisation succeeded
	// the next outage uses a new lock, so locks never have to be deleted
	lockKey := sf.key(login.groupID, resyncLockSuffix+":"+strconv.FormatInt(gen, 10))

	if sf.heldLock != lockKey || !time.Now().Before(sf.heldUntil) {
		ttl := lockTTL()
		// local deadline taken before the lock is set, so it ends before the lock
		until := time.Now().Add(ttl - ttl/10)

		acquired, err := sf.store.Lock(lockKey, ttl)
		switch {
		case err != nil:
			// can't coordinate with the group, keep any request for the next login
			Log.WithError(err).Error("error acquiring syncforcer resync lock")
			return false
		case !acquired:
			// another gateway of the group is forcing the synchronisation. The
			// record stays in the shared storage until it succeeds, so it is
			// picked up by the next login once the lock expires.
			sf.resyncRequested = false
			sf.resyncUnrecorded = false
			Log.Info("MDCB synchronization already in progress for group, skipping:", login.groupID)
			return false
		}

		sf.heldLock = lockKey
		sf.heldUntil = until
	}

	Log.Info("Forcing MDCB synchronization after reconnection for group:", login.groupID)
	return true
}

// groupLoginResult must be called with the result of the login request built
// by GroupLoginCallback.
func (sf *SyncronizerForcer) groupLoginResult(success bool) {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	login := sf.pending
	sf.pending = nil

	if success {
		// connected to MDCB again, a later connection loss is a new outage
		sf.inOutage = false
	}

	if login == nil {
		return
	}

	if success {
		// MDCB accepted the forced synchronisation of the group: bump the
		// generation first, so gateways still reconnecting from the same outage
		// see it was served, then drop the record. The lock of the old
		// generation is left to expire.
		sf.store.IncrememntWithExpire(sf.key(login.groupID, resyncGenSuffix), 0)
		sf.store.DeleteRawKey(sf.key(login.groupID, resyncNeededSuffix))
		sf.heldLock = ""
		return
	}

	// MDCB didn't get the request: ask again on the next login. The request is
	// recorded in the shared storage, so any gateway of the group can serve it,
	// also after a restart of this one.
	sf.groupID = login.groupID
	sf.requestResyncLocked()
}

func (sf *SyncronizerForcer) requestResyncLocked() {
	// before its first login a gateway hasn't processed any keyspace event, so
	// it can't have lost keys, and a fresh storage is resynchronised by the
	// group key check anyway. Ignoring such requests keeps gateways that fail
	// to reach MDCB while starting from each forcing a synchronisation.
	if sf.groupID == "" {
		Log.Debug("Ignoring MDCB synchronization request before the first group login")
		return
	}

	gen, err := sf.resyncGeneration(sf.groupID)
	if err != nil {
		Log.WithError(err).Error("error reading syncforcer resync generation")
		sf.resyncRequested = true
		sf.resyncUnrecorded = !sf.markResyncNeeded(sf.groupID)
		return
	}

	if !sf.inOutage {
		sf.inOutage = true
		sf.outageGen = gen
	}

	if gen > sf.outageGen {
		// a gateway of the group already forced a synchronisation since this
		// gateway lost the connection to MDCB, e.g. it reconnects later than
		// the others after the same outage
		sf.resyncRequested = false
		sf.resyncUnrecorded = false
		return
	}

	sf.resyncRequested = true
	sf.resyncUnrecorded = !sf.markResyncNeeded(sf.groupID)
}

// outageServedLocked reports whether the group was resynchronised since this
// gateway lost the connection to MDCB.
func (sf *SyncronizerForcer) outageServedLocked(groupID string) bool {
	if !sf.inOutage {
		return false
	}

	gen, err := sf.resyncGeneration(groupID)
	if err != nil {
		return false
	}

	return gen > sf.outageGen
}

// markResyncNeeded records in the shared storage that the group must be
// resynchronised. It reports whether the record exists afterwards.
func (sf *SyncronizerForcer) markResyncNeeded(groupID string) bool {
	// set if not exists, without expiry
	if _, err := sf.store.Lock(sf.key(groupID, resyncNeededSuffix), 0); err != nil {
		Log.WithError(err).Error("error recording syncforcer resync request")
		return false
	}

	return true
}

func (sf *SyncronizerForcer) isResyncNeeded(groupID string) (bool, error) {
	_, err := sf.store.GetRawKey(sf.key(groupID, resyncNeededSuffix))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, storage.ErrKeyNotFound):
		return false, nil
	default:
		return false, err
	}
}

// resyncGeneration returns the number of forced synchronisations of the group
// that reached MDCB, 0 when there was none.
func (sf *SyncronizerForcer) resyncGeneration(groupID string) (int64, error) {
	value, err := sf.store.GetRawKey(sf.key(groupID, resyncGenSuffix))
	switch {
	case err == nil:
		return strconv.ParseInt(value, 10, 64)
	case errors.Is(err, storage.ErrKeyNotFound):
		return 0, nil
	default:
		return 0, err
	}
}

func (sf *SyncronizerForcer) key(groupID, suffix string) string {
	return syncForcerKeyPrefix + groupID + suffix
}

// notifyGroupLoginResult reports the result of a group login to the sync
// forcer, if the synchroniser is in use.
func notifyGroupLoginResult(success bool) {
	if syncForcerInstance == nil {
		return
	}
	syncForcerInstance.groupLoginResult(success)
}
