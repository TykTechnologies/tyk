package auth

import (
	"encoding/json"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/gateway/model"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type SessionManager struct {
	store  storage.Handler
	cache  cache.Repository
	logger *logrus.Entry

	Gw model.GatewayInterface `json:"-"`
}

// NewSessionManager creates a new instance of *SessionManager
func NewSessionManager(gw model.GatewayInterface, store storage.Handler, cache cache.Repository, logger *logrus.Logger) *SessionManager {
	return &SessionManager{
		store:  store,
		cache:  cache,
		logger: logger.WithField("prefix", "auth-mgr"),
		Gw:     gw,
	}
}

func (b *SessionManager) Init(store storage.Handler) {
	b.store = store
	b.store.Connect()
}

// KeyExpired checks if a key has expired, if the value of user.SessionState.Expires is 0, it will be ignored
func (b *SessionManager) KeyExpired(newSession *user.SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}

func (b *SessionManager) Store() storage.Handler {
	return b.store
}

func (b *SessionManager) ResetQuota(keyName string, session *user.SessionState, isHashed bool) {
	origKeyName := keyName
	if !isHashed {
		keyName = storage.HashKey(keyName, b.Gw.GetConfig().HashKeys)
	}

	rawKey := model.QuotaKeyPrefix + keyName
	b.logger.WithFields(logrus.Fields{
		"inbound-key": b.Gw.ObfuscateKey(origKeyName),
		"key":         rawKey,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := model.RateLimitKeyPrefix + keyName + ".BLOCKED"

	// Clear the rate limiter
	b.store.DeleteRawKey(rateLimiterSentinelKey)
	// Fix the raw key
	b.store.DeleteRawKey(rawKey)

	for _, acl := range session.AccessRights {
		rawKey = model.QuotaKeyPrefix + acl.AllowanceScope + "-" + keyName
		b.store.DeleteRawKey(rawKey)
	}
}

func (b *SessionManager) clearCacheForKey(keyName string, hashed bool) {
	cacheKey := keyName
	if !hashed {
		cacheKey = storage.HashKey(keyName, b.Gw.GetConfig().HashKeys)
	}

	// Delete gateway's cache immediately
	b.cache.Delete(cacheKey)

	// Notify gateways in cluster to flush cache
	n := model.Notification{
		Command: model.KeySpaceUpdateNotification,
		Payload: cacheKey,
		Gw:      b.Gw,
	}
	b.Gw.Notify(n)
}

// UpdateSession updates the session state in the storage engine
func (b *SessionManager) UpdateSession(keyName string, session *user.SessionState,
	resetTTLTo int64, hashed bool) error {
	defer b.clearCacheForKey(keyName, hashed)

	v, err := json.Marshal(session)
	if err != nil {
		b.logger.Error("Error marshalling session for sync update")
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
func (b *SessionManager) RemoveSession(orgID string, keyName string, hashed bool) bool {
	defer b.clearCacheForKey(keyName, hashed)

	if hashed {
		return b.store.DeleteRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		// support both old and new key hashing
		res1 := b.store.DeleteKey(keyName)
		res2 := b.store.DeleteKey(b.Gw.GenerateToken(orgID, keyName))
		return res1 || res2
	}
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *SessionManager) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	var jsonKeyVal string
	var err error
	keyId := keyName

	// get session by key
	if hashed {
		jsonKeyVal, err = b.store.GetRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		if storage.TokenOrg(keyName) != orgID {
			// try to get legacy and new format key at once
			toSearchList := []string{b.Gw.GenerateToken(orgID, keyName), keyName}
			for _, fallback := range b.Gw.GetConfig().HashKeyFunctionFallback {
				toSearchList = append(toSearchList, b.Gw.GenerateToken(orgID, keyName, fallback))
			}

			var jsonKeyValList []string

			jsonKeyValList, err = b.store.GetMultiKey(toSearchList)

			// pick the 1st non empty from the returned list
			for idx, val := range jsonKeyValList {
				if val != "" {
					jsonKeyVal = val
					keyId = toSearchList[idx]
					break
				}
			}
		} else {
			// key is not an imported one
			jsonKeyVal, err = b.store.GetKey(keyName)
		}
	}

	if err != nil {
		b.logger.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": b.Gw.ObfuscateKey(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return user.SessionState{}, false
	}
	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(jsonKeyVal), &session); err != nil {
		b.logger.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return user.SessionState{}, false
	}
	session.KeyID = keyId
	return session.Clone(), true
}

func (b *SessionManager) Stop() {}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *SessionManager) Sessions(filter string) []string {
	return b.store.GetKeys(filter)
}
