package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/Sirupsen/logrus"
)

// AuthorisationHandler is used to validate a session key,
// implementing KeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	Init(storage.Handler)
	KeyAuthorised(string) (SessionState, bool)
	KeyExpired(*SessionState) bool
}

// SessionHandler handles all update/create/access session functions and deals exclusively with
// SessionState objects, not identity
type SessionHandler interface {
	Init(store storage.Handler)
	UpdateSession(keyName string, session *SessionState, resetTTLTo int64) error
	RemoveSession(keyName string)
	SessionDetail(keyName string) (SessionState, bool)
	Sessions(filter string) []string
	Store() storage.Handler
	ResetQuota(string, *SessionState)
}

// DefaultAuthorisationManager implements AuthorisationHandler,
// requires a storage.Handler to interact with key store
type DefaultAuthorisationManager struct {
	store storage.Handler
}

type DefaultSessionManager struct {
	store storage.Handler
}

func (b *DefaultAuthorisationManager) Init(store storage.Handler) {
	b.store = store
	b.store.Connect()
}

// KeyAuthorised checks if key exists and can be read into a SessionState object
func (b *DefaultAuthorisationManager) KeyAuthorised(keyName string) (SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(keyName)
	var newSession SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKeyString(keyName),
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

// KeyExpired checks if a key has expired, if the value of SessionState.Expires is 0, it will be ignored
func (b *DefaultAuthorisationManager) KeyExpired(newSession *SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}

func (b *DefaultSessionManager) Init(store storage.Handler) {
	b.store = store
	b.store.Connect()
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session *SessionState) {

	rawKey := QuotaKeyPrefix + storage.HashKey(keyName)
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": ObfuscateKeyString(keyName),
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
func (b *DefaultSessionManager) UpdateSession(keyName string, session *SessionState, resetTTLTo int64) error {
	if !session.HasChanged() {
		log.Debug("Session has not changed, not updating")
		return nil
	}

	v, _ := json.Marshal(session)

	// Keep the TTL
	if config.Global.UseAsyncSessionWrite {
		go b.store.SetKey(keyName, string(v), resetTTLTo)
		return nil
	}
	return b.store.SetKey(keyName, string(v), resetTTLTo)
}

func (b *DefaultSessionManager) RemoveSession(keyName string) {
	b.store.DeleteKey(keyName)
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(keyName string) (SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(keyName)
	var session SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKeyString(keyName),
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
