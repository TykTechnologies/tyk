package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/TykTechnologies/gorpc"

	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// masterKeyState is the outcome of reading a key from the control plane through MDCB.
type masterKeyState int

const (
	// masterKeyFound means MDCB returned the key.
	masterKeyFound masterKeyState = iota
	// masterKeyNotFound means MDCB answered, but the key is not available on the control plane.
	masterKeyNotFound
	// masterKeyUnavailable means MDCB couldn't be reached (emergency mode, connection or timeout errors).
	masterKeyUnavailable
)

// keyUpdate is the outcome of an in-place update of a key from a keyspace event.
type keyUpdate int

const (
	// keyUpdateFallback means the key was not updated in place and must go through
	// the delete-and-recreate path.
	keyUpdateFallback keyUpdate = iota
	// keyUpdateUnavailable is keyUpdateFallback because MDCB couldn't be reached.
	keyUpdateUnavailable
	// keyUpdateUnchanged means the local copy already matches the control plane.
	keyUpdateUnchanged
	// keyUpdateApplied means the local copy was overwritten with the control plane version.
	keyUpdateApplied
)

// updateKeyInPlace refreshes a key from the control plane without removing it first
// (TT-15569). The key is never missing while it is updated, and a key that didn't
// change causes no write and no cache flush notification, which matters when MDCB
// resynchronises a whole group.
//
// Only keys stored locally under the name the update writes to are handled here.
// Keys that don't exist locally (first synchronisation), are stored under another
// (legacy) name, were removed from the control plane or can't be fetched are left to
// the delete-and-recreate path, so their handling is unchanged.
func (r *RPCStorageHandler) updateKeyInPlace(event string, isHashed bool, orgId string) keyUpdate {
	key := event
	if isHashed {
		key = strings.Split(event, ":")[0]
	} else if storage.TokenOrg(key) == "" {
		// username (basic auth) or custom key
		key = r.Gw.generateToken(orgId, key)
	}

	keyHash := key
	if !isHashed {
		keyHash = storage.HashKey(key, r.Gw.GetConfig().HashKeys)
	}

	store := r.Gw.GlobalSessionManager.Store()
	if store == nil {
		return keyUpdateFallback
	}

	localSession, err := store.GetRawKey(store.GetKeyPrefix() + keyHash)
	if err != nil {
		return keyUpdateFallback
	}

	remoteSession, state := r.fetchKeyFromMaster("apikey-" + keyHash)
	switch state {
	case masterKeyNotFound:
		return keyUpdateFallback
	case masterKeyUnavailable:
		return keyUpdateUnavailable
	}

	remote := &user.SessionState{}
	if err := json.Unmarshal([]byte(remoteSession), remote); err != nil || remote.OrgID != orgId {
		// let the delete-and-recreate path handle (and log) it as before
		return keyUpdateFallback
	}

	if sessionsEqual(localSession, remote) {
		log.Debug("--> key unchanged, skipping update: ", r.Gw.obfuscateKey(keyHash))
		return keyUpdateUnchanged
	}

	log.Info("--> updating cached key in place: ", r.Gw.obfuscateKey(keyHash))
	r.Gw.handleAddKey(keyHash, remoteSession, orgId)
	r.Gw.SessionCache.Delete(keyHash)

	return keyUpdateApplied
}

// fetchKeyFromMaster reads a key from MDCB, bypassing the RPC cache. Unlike GetRawKey it
// tells a key that MDCB couldn't return apart from MDCB being unreachable.
func (r *RPCStorageHandler) fetchKeyFromMaster(keyName string) (string, masterKeyState) {
	// a cached value may predate the change being processed
	r.Gw.RPCGlobalCache.Delete(keyName)

	if rpc.IsEmergencyMode() {
		return "", masterKeyUnavailable
	}

	value, err := rpc.FuncClientSingleton("GetKey", keyName)
	if err != nil && r.IsRetriableError(err) && rpc.Login() {
		value, err = rpc.FuncClientSingleton("GetKey", keyName)
	}

	if err != nil {
		if isMasterAnswer(err) && !r.IsRetriableError(err) {
			return "", masterKeyNotFound
		}

		log.WithError(err).Debug("Couldn't fetch key from master")
		return "", masterKeyUnavailable
	}

	session, ok := value.(string)
	if !ok {
		return "", masterKeyUnavailable
	}

	return session, masterKeyFound
}

// isMasterAnswer reports whether the RPC error was returned by MDCB itself (e.g. key not
// found), as opposed to a connection or timeout error.
func isMasterAnswer(err error) bool {
	var clientErr *gorpc.ClientError
	return errors.As(err, &clientErr) && clientErr.Server
}

// sessionsEqual reports whether the stored session matches the control plane session,
// ignoring LastUpdated, which the gateway sets when it stores a key.
func sessionsEqual(localSession string, remote *user.SessionState) bool {
	local := &user.SessionState{}
	if err := json.Unmarshal([]byte(localSession), local); err != nil {
		return false
	}

	local.LastUpdated = remote.LastUpdated

	localJSON, err := json.Marshal(local)
	if err != nil {
		return false
	}

	remoteJSON, err := json.Marshal(remote)
	if err != nil {
		return false
	}

	return bytes.Equal(localJSON, remoteJSON)
}

// keyspaceNotificationPayload returns the keyspace events that other gateways must flush
// from their caches, i.e. all events except the keys that didn't change.
func keyspaceNotificationPayload(keys []string, unchanged map[string]bool) string {
	if len(unchanged) == 0 {
		return strings.Join(keys, ",")
	}

	notify := make([]string, 0, len(keys))
	for _, key := range keys {
		if !unchanged[key] {
			notify = append(notify, key)
		}
	}

	return strings.Join(notify, ",")
}

// requestResync asks for a forced synchronisation of the group, e.g. when keys couldn't
// be fetched from MDCB (TT-12417). Only one gateway of the group forces it.
func (r *RPCStorageHandler) requestResync() {
	if !r.Gw.GetConfig().SlaveOptions.SynchroniserEnabled {
		return
	}

	rpc.NewSyncForcer(r.Gw.StorageConnectionHandler, r.buildNodeInfo).RequestResync()
}
