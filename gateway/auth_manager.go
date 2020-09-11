package gateway

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"

	"github.com/sirupsen/logrus"
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
	RemoveSession(orgID string, keyName string, hashed bool) bool
	SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool)
	Sessions(filter string) []string
	Store() storage.Handler
	ResetQuota(string, *user.SessionState, bool)
	Stop()
}

const sessionPoolDefaultSize = 50
const sessionBufferDefaultSize = 1000

type sessionUpdater struct {
	store      storage.Handler
	once       sync.Once
	updateChan chan *SessionUpdate
	poolSize   int
	bufferSize int
	keyPrefix  string
}

var defaultSessionUpdater *sessionUpdater

func init() {
	defaultSessionUpdater = &sessionUpdater{}
}

func (s *sessionUpdater) Init(store storage.Handler) {
	s.once.Do(func() {
		s.store = store
		// check pool size in config and set to 50 if unset
		s.poolSize = config.Global().SessionUpdatePoolSize
		if s.poolSize <= 0 {
			s.poolSize = sessionPoolDefaultSize
		}
		//check size for channel buffer and set to 1000 if unset
		s.bufferSize = config.Global().SessionUpdateBufferSize
		if s.bufferSize <= 0 {
			s.bufferSize = sessionBufferDefaultSize
		}

		log.WithField("pool_size", s.poolSize).Debug("Session update async pool size")

		s.updateChan = make(chan *SessionUpdate, s.bufferSize)

		s.keyPrefix = s.store.GetKeyPrefix()

		for i := 0; i < s.poolSize; i++ {
			go s.updateWorker()
		}
	})
}

func (s *sessionUpdater) updateWorker() {
	for u := range s.updateChan {
		v, err := json.Marshal(u.session)
		if err != nil {
			log.WithError(err).Error("Error marshalling session for async session update")
			continue
		}

		if u.isHashed {
			u.keyVal = s.keyPrefix + u.keyVal
			err := s.store.SetRawKey(u.keyVal, string(v), u.ttl)
			if err != nil {
				log.WithError(err).Error("Error updating hashed key")
			}
			continue

		}

		err = s.store.SetKey(u.keyVal, string(v), u.ttl)
		if err != nil {
			log.WithError(err).Error("Error updating key")
		}
	}
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
	orgID                    string
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
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": obfuscateKey(keyName),
			"err":         err,
		}).Warning("Key not found in storage engine")
		return user.SessionState{}, false
	}
	newSession := &user.SessionState{}
	if err := json.Unmarshal([]byte(jsonKeyVal), newSession); err != nil {
		log.Error("Couldn't unmarshal session object: ", err)
		return user.SessionState{}, false
	}
	return newSession.Clone(), true
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

	// for RPC we don't need to setup async session writes
	switch store.(type) {
	case *RPCStorageHandler:
		return
	}

	if b.asyncWrites {
		defaultSessionUpdater.Init(store)
	}
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session *user.SessionState, isHashed bool) {
	origKeyName := keyName
	if !isHashed {
		keyName = storage.HashKey(keyName)
	}

	rawKey := QuotaKeyPrefix + keyName
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": obfuscateKey(origKeyName),
		"key":         rawKey,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := RateLimitKeyPrefix + keyName + ".BLOCKED"
	// Clear the rate limiter
	go b.store.DeleteRawKey(rateLimiterSentinelKey)
	// Fix the raw key
	go b.store.DeleteRawKey(rawKey)
	//go b.store.SetKey(rawKey, "0", session.QuotaRenewalRate)

	for _, acl := range session.GetAccessRights() {
		rawKey = QuotaKeyPrefix + acl.AllowanceScope + "-" + keyName
		go b.store.DeleteRawKey(rawKey)
	}
}

func (b *DefaultSessionManager) clearCacheForKey(keyName string, hashed bool) {
	cacheKey := keyName
	if !hashed {
		cacheKey = storage.HashKey(keyName)
	}

	// Delete current gateway's cache immediately
	SessionCache.Delete(cacheKey)

	// Notify gateways in cluster to flush cache
	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: cacheKey,
	}
	MainNotifier.Notify(n)
}

// UpdateSession updates the session state in the storage engine
func (b *DefaultSessionManager) UpdateSession(keyName string, session *user.SessionState,
	resetTTLTo int64, hashed bool) error {
	defer b.clearCacheForKey(keyName, hashed)

	// async update and return if needed
	if b.asyncWrites {
		sessionUpdate := &SessionUpdate{
			isHashed: hashed,
			keyVal:   keyName,
			session:  session,
			ttl:      resetTTLTo,
		}

		// send sessionupdate object through channel to pool
		defaultSessionUpdater.updateChan <- sessionUpdate

		return nil
	}

	v, err := json.Marshal(session)
	if err != nil {
		log.Error("Error marshalling session for sync update")
		return err
	}

	// sync update
	if hashed {
		keyName = b.store.GetKeyPrefix() + keyName
		err = b.store.SetRawKey(keyName, string(v), resetTTLTo)
	} else {
		err = b.store.SetKey(keyName, string(v), resetTTLTo)
	}

	return err
}

// RemoveSession removes session from storage
func (b *DefaultSessionManager) RemoveSession(orgID string, keyName string, hashed bool) bool {
	defer b.clearCacheForKey(keyName, hashed)

	if hashed {
		return b.store.DeleteRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		// support both old and new key hashing
		res1 := b.store.DeleteKey(keyName)
		res2 := b.store.DeleteKey(generateToken(orgID, keyName))
		return res1 || res2
	}
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	var jsonKeyVal string
	var err error

	// get session by key
	if hashed {
		jsonKeyVal, err = b.store.GetRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		if storage.TokenOrg(keyName) != orgID {
			// try to get legacy and new format key at once
			var jsonKeyValList []string
			jsonKeyValList, err = b.store.GetMultiKey(
				[]string{
					generateToken(orgID, keyName),
					keyName,
				},
			)

			// pick the 1st non empty from the returned list
			for _, val := range jsonKeyValList {
				if val != "" {
					jsonKeyVal = val
					break
				}
			}
		} else {
			// key is not an imported one
			jsonKeyVal, err = b.store.GetKey(keyName)
		}
	}

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": obfuscateKey(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return user.SessionState{}, false
	}
	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(jsonKeyVal), &session); err != nil {
		log.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return user.SessionState{}, false
	}

	return session.Clone(), true
}

func (b *DefaultSessionManager) Stop() {}

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
