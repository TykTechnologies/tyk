package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"

	"github.com/Sirupsen/logrus"
)

// AuthorisationHandler is used to validate a session key,
// implementing KeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a user.SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	Init(storage.Handler)
	KeyAuthorised(string) (user.SessionState, bool)
	KeyExpired(*user.SessionState) bool
}

// SessionHandler handles all update/create/access session functions and deals exclusively with
// user.SessionState objects, not identity
type SessionHandler interface {
	Init(store storage.Handler)
	UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error
	RemoveSession(keyName string, hashed bool)
	SessionDetail(keyName string, hashed bool) (user.SessionState, bool)
	Sessions(filter string) []string
	Store() storage.Handler
	ResetQuota(string, *user.SessionState)
}

// DefaultAuthorisationManager implements AuthorisationHandler,
// requires a storage.Handler to interact with key store
type DefaultAuthorisationManager struct {
	store storage.Handler
}

type DefaultSessionManager struct {
	store                    storage.Handler
	asyncWrites              bool
	disableCacheSessionState bool
}

func (b *DefaultAuthorisationManager) Init(store storage.Handler) {
	b.store = store
	b.store.Connect()
}

// KeyAuthorised checks if key exists and can be read into a user.SessionState object
func (b *DefaultAuthorisationManager) KeyAuthorised(keyName string) (user.SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(keyName)
	var newSession user.SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": obfuscateKey(keyName),
			"err":         err,
		}).Warning("Key not found in storage engine")
		return newSession, false
	}

	if err := json.Unmarshal([]byte(jsonKeyVal), &newSession); err != nil {
		log.Error("Couldn't unmarshal session object: ", err)
		return newSession, false
	}

	newSession.SetFirstSeenHash()
	return newSession, true
}

// KeyExpired checks if a key has expired, if the value of user.SessionState.Expires is 0, it will be ignored
func (b *DefaultAuthorisationManager) KeyExpired(newSession *user.SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}

func (b *DefaultSessionManager) Init(store storage.Handler) {
	b.asyncWrites = config.Global().UseAsyncSessionWrite
	b.disableCacheSessionState = config.Global().LocalSessionCache.DisableCacheSessionState
	b.store = store
	b.store.Connect()
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session *user.SessionState) {

	rawKey := QuotaKeyPrefix + storage.HashKey(keyName)
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": obfuscateKey(keyName),
		"key":         rawKey,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := RateLimitKeyPrefix + storage.HashKey(keyName) + ".BLOCKED"
	// Clear the rate limiter
	go b.store.DeleteRawKey(rateLimiterSentinelKey)
	// Fix the raw key
	go b.store.DeleteRawKey(rawKey)
	//go b.store.SetKey(rawKey, "0", session.QuotaRenewalRate)
}

// UpdateSession updates the session state in the storage engine
func (b *DefaultSessionManager) UpdateSession(keyName string, session *user.SessionState,
	resetTTLTo int64, hashed bool) error {
	if !session.HasChanged() {
		log.Debug("Session has not changed, not updating")
		return nil
	}

	v, _ := json.Marshal(session)

	if hashed {
		keyName = b.store.GetKeyPrefix() + keyName
	}

	// async update and return if needed
	if b.asyncWrites {
		b.renewSessionState(keyName, session)

		if hashed {
			go b.store.SetRawKey(keyName, string(v), resetTTLTo)
			return nil
		}

		go b.store.SetKey(keyName, string(v), resetTTLTo)
		return nil
	}

	// sync update
	var err error
	if hashed {
		err = b.store.SetRawKey(keyName, string(v), resetTTLTo)
	} else {
		err = b.store.SetKey(keyName, string(v), resetTTLTo)
	}

	if err == nil {
		b.renewSessionState(keyName, session)
	}

	return err
}

func (b *DefaultSessionManager) renewSessionState(keyName string, session *user.SessionState) {
	// we have new session state so renew first-seen hash to prevent
	session.SetFirstSeenHash()
	// delete it from session cache to have it re-populated next time
	if !b.disableCacheSessionState {
		SessionCache.Delete(keyName)
	}
}

// RemoveSession removes session from storage
func (b *DefaultSessionManager) RemoveSession(keyName string, hashed bool) {
	if hashed {
		b.store.DeleteRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		b.store.DeleteKey(keyName)
	}
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(keyName string, hashed bool) (user.SessionState, bool) {
	var jsonKeyVal string
	var err error
	var session user.SessionState

	// get session by key
	if hashed {
		jsonKeyVal, err = b.store.GetRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		jsonKeyVal, err = b.store.GetKey(keyName)
	}

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": obfuscateKey(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return session, false
	}

	if err := json.Unmarshal([]byte(jsonKeyVal), &session); err != nil {
		log.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return session, false
	}

	session.SetFirstSeenHash()

	return session, true
}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(filter string) []string {
	return b.store.GetKeys(filter)
}

type DefaultKeyGenerator struct{}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateAuthKey(orgID string) string {
	u5 := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	return orgID + cleanSting
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateHMACSecret() string {
	u5 := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	return base64.StdEncoding.EncodeToString([]byte(cleanSting))
}
