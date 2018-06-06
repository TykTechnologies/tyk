package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
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
	Stop()
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
	updateChan               chan *SessionUpdate
	poolSize                 int
	shouldStop               uint32
	poolWG                   sync.WaitGroup
	bufferSize               int
	keyPrefix                string
}

type SessionUpdate struct {
	isHashed bool
	keyVal   string
	session  *user.SessionState
	ttl      int64
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
	b.store = store
	b.store.Connect()

	if b.asyncWrites {
		// check pool size in config and set to 50 if unset
		b.poolSize = config.Global().SessionUpdatePoolSize
		if b.poolSize <= 0 {
			b.poolSize = 50
		}
		//check size for channel buffer and set to 1000 if unset
		b.bufferSize = config.Global().SessionUpdateBufferSize
		if b.bufferSize <= 0 {
			b.bufferSize = 1000
		}

		log.WithField("Auth Manager", b.poolSize).Debug("Session update async pool size")

		b.updateChan = make(chan *SessionUpdate, b.bufferSize)

		b.keyPrefix = b.store.GetKeyPrefix()

		//start worker pool
		atomic.SwapUint32(&b.shouldStop, 0)
		for i := 0; i < b.poolSize; i++ {
			b.poolWG.Add(1)
			go b.updateWorker()
		}
	}
}

func (b *DefaultSessionManager) updateWorker() {
	defer b.poolWG.Done()

	for range b.updateChan {
		// grab update object from channel
		u := <-b.updateChan

		v, err := json.Marshal(u.session)
		if err != nil {
			log.Error("Error marshalling session for async session update")
			continue
		}

		if u.isHashed {
			u.keyVal = b.keyPrefix + u.keyVal
			err := b.store.SetRawKey(u.keyVal, string(v), u.ttl)
			if err != nil {
				log.Errorf("Error updating hashed key: %v", err)
			}
			continue

		}

		err = b.store.SetKey(u.keyVal, string(v), u.ttl)
		if err != nil {
			log.Errorf("Error updating non-hashed key: %v", err)
		}
	}
}

func (b *DefaultSessionManager) Stop() {
	if atomic.LoadUint32(&b.shouldStop) == 0 {
		// flag to stop adding data to chan
		atomic.SwapUint32(&b.shouldStop, 1)
		// close update channel
		close(b.updateChan)
		// wait for workers to finish
		b.poolWG.Wait()
	}
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

	// async update and return if needed
	if b.asyncWrites {
		if atomic.LoadUint32(&b.shouldStop) > 0 {
			return nil
		}

		sessionUpdate := &SessionUpdate{
			isHashed: hashed,
			keyVal:   keyName,
			session:  session,
			ttl:      resetTTLTo,
		}

		// send sessionupdate object through channel to pool
		b.updateChan <- sessionUpdate

		return nil
	}

	v, err := json.Marshal(session)
	if err != nil {
		log.Error("Error marshalling session for sync update")
		return err
	}

	if hashed {
		keyName = b.store.GetKeyPrefix() + keyName
	}

	// sync update
	if hashed {
		err = b.store.SetRawKey(keyName, string(v), resetTTLTo)
	} else {
		err = b.store.SetKey(keyName, string(v), resetTTLTo)
	}

	return err
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

	return session, true
}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(filter string) []string {
	return b.store.GetKeys(filter)
}

type DefaultKeyGenerator struct{}

func generateToken(orgID, keyID string) string {
	keyID = strings.TrimPrefix(keyID, orgID)
	token, err := storage.GenerateToken(orgID, keyID, config.Global().HashKeyFunction)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "auth-mgr",
			"orgID":  orgID,
		}).WithError(err).Warning("Issue during token generation")
	}

	return token
}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateAuthKey(orgID string) string {
	return generateToken(orgID, "")
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateHMACSecret() string {
	u5 := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	return base64.StdEncoding.EncodeToString([]byte(cleanSting))
}
