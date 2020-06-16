package gateway

import (
	"context"
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
	Init(context.Context, storage.Handler)
	KeyAuthorised(context.Context, string) (user.SessionState, bool)
	KeyExpired(context.Context, *user.SessionState) bool
}

// SessionHandler handles all update/create/access session functions and deals exclusively with
// user.SessionState objects, not identity
type SessionHandler interface {
	Init(ctx context.Context, store storage.Handler)
	UpdateSession(ctx context.Context, keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error
	RemoveSession(ctx context.Context, orgID string, keyName string, hashed bool) bool
	SessionDetail(ctx context.Context, orgID string, keyName string, hashed bool) (user.SessionState, bool)
	Sessions(ctx context.Context, filter string) []string
	Store() storage.Handler
	ResetQuota(context.Context, string, *user.SessionState, bool)
	Stop(ctx context.Context)
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

func (s *sessionUpdater) Init(ctx context.Context, store storage.Handler) {
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

		s.keyPrefix = s.store.GetKeyPrefix(ctx)

		for i := 0; i < s.poolSize; i++ {
			go s.updateWorker(ctx)
		}
	})
}

func (s *sessionUpdater) updateWorker(ctx context.Context) {
	for u := range s.updateChan {
		v, err := json.Marshal(u.session)
		if err != nil {
			log.WithError(err).Error("Error marshalling session for async session update")
			continue
		}

		if u.isHashed {
			u.keyVal = s.keyPrefix + u.keyVal
			err := s.store.SetRawKey(ctx, u.keyVal, string(v), u.ttl)
			if err != nil {
				log.WithError(err).Error("Error updating hashed key")
			}
			continue

		}

		err = s.store.SetKey(ctx, u.keyVal, string(v), u.ttl)
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

func (b *DefaultAuthorisationManager) Init(ctx context.Context, store storage.Handler) {
	b.store = store
	b.store.Connect(ctx)
}

// KeyAuthorised checks if key exists and can be read into a user.SessionState object
func (b *DefaultAuthorisationManager) KeyAuthorised(ctx context.Context, keyName string) (user.SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(ctx, keyName)
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
func (b *DefaultAuthorisationManager) KeyExpired(ctx context.Context, newSession *user.SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}

func (b *DefaultSessionManager) Init(ctx context.Context, store storage.Handler) {
	b.asyncWrites = config.Global().UseAsyncSessionWrite
	b.store = store
	b.store.Connect(ctx)

	// for RPC we don't need to setup async session writes
	switch store.(type) {
	case *RPCStorageHandler:
		return
	}

	if b.asyncWrites {
		defaultSessionUpdater.Init(ctx, store)
	}
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(ctx context.Context, keyName string, session *user.SessionState, isHashed bool) {
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
	// We are deliberatelycalling redis directly instead of the separate goroutine.
	// This piece is important we need to have deterministic expectations.

	// Clear the rate limiter
	b.store.DeleteRawKey(ctx, rateLimiterSentinelKey)
	// Fix the raw key
	b.store.DeleteRawKey(ctx, rawKey)
	//go b.store.SetKey(rawKey, "0", session.QuotaRenewalRate)

	for _, acl := range session.AccessRights {
		rawKey = QuotaKeyPrefix + acl.AllowanceScope + "-" + keyName
		b.store.DeleteRawKey(ctx, rawKey)
	}
}

func (b *DefaultSessionManager) clearCacheForKey(ctx context.Context, keyName string, hashed bool) {
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
	MainNotifier.Notify(ctx, n)
}

// UpdateSession updates the session state in the storage engine
func (b *DefaultSessionManager) UpdateSession(ctx context.Context, keyName string, session *user.SessionState,
	resetTTLTo int64, hashed bool) error {
	defer b.clearCacheForKey(ctx, keyName, hashed)

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
		keyName = b.store.GetKeyPrefix(ctx) + keyName
		err = b.store.SetRawKey(ctx, keyName, string(v), resetTTLTo)
	} else {
		err = b.store.SetKey(ctx, keyName, string(v), resetTTLTo)
	}

	return err
}

// RemoveSession removes session from storage
func (b *DefaultSessionManager) RemoveSession(ctx context.Context, orgID string, keyName string, hashed bool) bool {
	defer b.clearCacheForKey(ctx, keyName, hashed)

	if hashed {
		return b.store.DeleteRawKey(ctx, b.store.GetKeyPrefix(ctx)+keyName)
	} else {
		// support both old and new key hashing
		res1 := b.store.DeleteKey(ctx, keyName)
		res2 := b.store.DeleteKey(ctx, generateToken(orgID, keyName))
		return res1 || res2
	}
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(ctx context.Context, orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	var jsonKeyVal string
	var err error
	var session user.SessionState

	// get session by key
	if hashed {
		jsonKeyVal, err = b.store.GetRawKey(ctx, b.store.GetKeyPrefix(ctx)+keyName)
	} else {
		if storage.TokenOrg(keyName) != orgID {
			// try to get legacy and new format key at once
			var jsonKeyValList []string
			jsonKeyValList, err = b.store.GetMultiKey(ctx,
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
			jsonKeyVal, err = b.store.GetKey(ctx, keyName)
		}
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

func (b *DefaultSessionManager) Stop(ctx context.Context) {}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(ctx context.Context, filter string) []string {
	return b.store.GetKeys(ctx, filter)
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
