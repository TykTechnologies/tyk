package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/TykTechnologies/logrus"
	"github.com/nu7hatch/gouuid"
)

// AuthorisationHandler is used to validate a session key,
// implementing IsKeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	Init(StorageHandler)
	IsKeyAuthorised(string) (SessionState, bool)
	IsKeyExpired(*SessionState) bool
}

// SessionHandler handles all update/create/access session functions and deals exclusively with
// SessionState objects, not identity
type SessionHandler interface {
	Init(store StorageHandler)
	UpdateSession(keyName string, session SessionState, resetTTLTo int64) error
	RemoveSession(keyName string)
	GetSessionDetail(keyName string) (SessionState, bool)
	GetSessions(filter string) []string
	GetStore() StorageHandler
	ResetQuota(string, SessionState)
}

type KeyGenerator interface {
	GenerateAuthKey(OrgID string) string
	GenerateHMACSecret() string
}

// DefaultAuthorisationManager implements AuthorisationHandler,
// requires a StorageHandler to interact with key store
type DefaultAuthorisationManager struct {
	Store StorageHandler
}

type DefaultSessionManager struct {
	Store StorageHandler
}

func (b *DefaultAuthorisationManager) Init(store StorageHandler) {
	b.Store = store
	b.Store.Connect()
}

// IsKeyAuthorised checks if key exists and can be read into a SessionState object
func (b DefaultAuthorisationManager) IsKeyAuthorised(keyName string) (SessionState, bool) {
	jsonKeyVal, err := b.Store.GetKey(keyName)
	var newSession SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKeyString(keyName),
			"err":         err,
		}).Warning("Key not found in storage engine")
		return newSession, false
	}

	if marshalErr := json.Unmarshal([]byte(jsonKeyVal), &newSession); marshalErr != nil {
		log.Error("Couldn't unmarshal session object")
		log.Error(marshalErr)
		return newSession, false
	}

	newSession.SetFirstSeenHash()
	return newSession, true
}

// IsKeyExpired checks if a key has expired, if the value of SessionState.Expires is 0, it will be ignored
func (b DefaultAuthorisationManager) IsKeyExpired(newSession *SessionState) bool {
	if newSession.Expires >= 1 {
		//diff := newSession.Expires - time.Now().Unix()
		if time.Now().After(time.Unix(newSession.Expires, 0)) {
			return true
		}
		return false
	}
	return false
}

func (b *DefaultSessionManager) Init(store StorageHandler) {
	b.Store = store
	b.Store.Connect()
}

func (b *DefaultSessionManager) GetStore() StorageHandler {
	return b.Store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session SessionState) {

	rawKey := QuotaKeyPrefix + publicHash(keyName)
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": ObfuscateKeyString(keyName),
		"key":         rawKey,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := RateLimitKeyPrefix + publicHash(keyName) + ".BLOCKED"
	// Clear the rate limiter
	go b.Store.DeleteRawKey(rateLimiterSentinelKey)
	// Fix the raw key
	go b.Store.DeleteRawKey(rawKey)
	//go b.Store.SetKey(rawKey, "0", session.QuotaRenewalRate)
}

// UpdateSession updates the session state in the storage engine
func (b DefaultSessionManager) UpdateSession(keyName string, session SessionState, resetTTLTo int64) error {
	if !session.HasChanged() {
		log.Debug("Session has not changed, not updating")
		return nil
	}

	v, _ := json.Marshal(session)

	// Keep the TTL
	if config.UseAsyncSessionWrite {
		go b.Store.SetKey(keyName, string(v), int64(resetTTLTo))
		return nil
	}
	err := b.Store.SetKey(keyName, string(v), int64(resetTTLTo))
	return err

}

func (b DefaultSessionManager) RemoveSession(keyName string) {
	b.Store.DeleteKey(keyName)
}

// GetSessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b DefaultSessionManager) GetSessionDetail(keyName string) (SessionState, bool) {
	jsonKeyVal, err := b.Store.GetKey(keyName)
	var thisSession SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKeyString(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return thisSession, false
	}

	if marshalErr := json.Unmarshal([]byte(jsonKeyVal), &thisSession); marshalErr != nil {
		log.Error("Couldn't unmarshal session object (may be cache miss): ", marshalErr)
		return thisSession, false
	}

	thisSession.SetFirstSeenHash()

	return thisSession, true
}

// GetSessions returns all sessions in the key store that match a filter key (a prefix)
func (b DefaultSessionManager) GetSessions(filter string) []string {
	return b.Store.GetKeys(filter)
}

type DefaultKeyGenerator struct {
}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (b DefaultKeyGenerator) GenerateAuthKey(OrgID string) string {
	u5, _ := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	newAuthKey := expandKey(OrgID, cleanSting)

	return newAuthKey
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (b DefaultKeyGenerator) GenerateHMACSecret() string {
	u5, _ := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	newSecret := base64.StdEncoding.EncodeToString([]byte(cleanSting))

	return newSecret
}
