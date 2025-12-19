package gateway

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// SessionHandler handles all update/create/access session functions and deals exclusively with
// user.SessionState objects, not identity
type SessionHandler interface {
	Init(store storage.Handler)
	Store() storage.Handler
	UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error
	RemoveSession(orgID string, keyName string, hashed bool) bool
	SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool)
	SessionDetailBulk(orgID string, keyNames []string, hashed bool) (map[string]user.SessionState, error)
	KeyExpired(newSession *user.SessionState) bool
	Sessions(filter string) []string
	ResetQuota(string, *user.SessionState, bool)
	Stop()
}

type DefaultSessionManager struct {
	store storage.Handler
	orgID string
	Gw    *Gateway `json:"-"`
}

func (b *DefaultSessionManager) ResetQuotaObfuscateKey(keyName string) string {
	if !b.Gw.GetConfig().HashKeys && !b.Gw.GetConfig().EnableKeyLogging {
		return b.Gw.obfuscateKey(keyName)
	}
	return keyName
}

func (b *DefaultSessionManager) Init(store storage.Handler) {
	b.store = store
	b.store.Connect()
}

// KeyExpired checks if a key has expired, if the value of user.SessionState.Expires is 0, it will be ignored
func (b *DefaultSessionManager) KeyExpired(newSession *user.SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session *user.SessionState, isHashed bool) {
	origKeyName := keyName

	if !isHashed {
		keyName = storage.HashKey(keyName, b.Gw.GetConfig().HashKeys)
	}

	rawKey := QuotaKeyPrefix + keyName
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": b.Gw.obfuscateKey(origKeyName),
		"key":         b.ResetQuotaObfuscateKey(keyName),
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := RateLimitKeyPrefix + keyName + ".BLOCKED"

	// Clear the rate limiter and
	// Fix the raw key
	defaultKeys := []string{rateLimiterSentinelKey, rawKey}
	keys := rawKeysWithAllowanceScope(defaultKeys, keyName, session)
	b.store.DeleteRawKeys(keys)
}

func rawKeysWithAllowanceScope(keys []string, keyName string, session *user.SessionState) []string {
	for _, acl := range session.AccessRights {
		if acl.AllowanceScope == "" {
			continue
		}
		keys = append(keys, QuotaKeyPrefix+acl.AllowanceScope+"-"+keyName)
	}
	return keys
}

func (b *DefaultSessionManager) deleteRawKeysWithAllowanceScope(store storage.Handler, session *user.SessionState, keyName string) {
	if store == nil || session == nil {
		return
	}

	for _, acl := range session.AccessRights {
		if acl.AllowanceScope == "" {
			continue
		}
		rawKey := QuotaKeyPrefix + acl.AllowanceScope + "-" + keyName
		store.DeleteRawKey(rawKey)
	}
}

func (b *DefaultSessionManager) clearCacheForKey(keyName string, hashed bool) {
	cacheKey := keyName
	if !hashed {
		cacheKey = storage.HashKey(keyName, b.Gw.GetConfig().HashKeys)
	}
	// Delete gateway's cache immediately
	b.Gw.SessionCache.Delete(cacheKey)

	// Notify gateways in cluster to flush cache
	n := Notification{
		Command: KeySpaceUpdateNotification,
		Payload: cacheKey,
		Gw:      b.Gw,
	}
	b.Gw.MainNotifier.Notify(n)
}

// UpdateSession updates the session state in the storage engine
func (b *DefaultSessionManager) UpdateSession(keyName string, session *user.SessionState,
	resetTTLTo int64, hashed bool) error {
	defer b.clearCacheForKey(keyName, hashed)

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
		res2 := b.store.DeleteKey(b.Gw.generateToken(orgID, keyName))
		return res1 || res2
	}
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	var jsonKeyVal string
	var err error
	keyId := keyName

	// get session by key
	if hashed {
		jsonKeyVal, err = b.store.GetRawKey(b.store.GetKeyPrefix() + keyName)
	} else {
		if storage.TokenOrg(keyName) != orgID {
			// try to get legacy and new format key at once
			toSearchList := []string{}
			if !b.Gw.GetConfig().DisableKeyActionsByUsername {
				toSearchList = append(toSearchList, b.Gw.generateToken(orgID, keyName))
			}

			toSearchList = append(toSearchList, keyName)
			for _, fallback := range b.Gw.GetConfig().HashKeyFunctionFallback {
				if !b.Gw.GetConfig().DisableKeyActionsByUsername {
					toSearchList = append(toSearchList, b.Gw.generateToken(orgID, keyName, fallback))
				}
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
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": b.Gw.obfuscateKey(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return user.SessionState{}, false
	}
	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(jsonKeyVal), &session); err != nil {
		log.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return user.SessionState{}, false
	}
	session.KeyID = keyId
	return session.Clone(), true
}

func (b *DefaultSessionManager) SessionDetailBulk(orgID string, keyNames []string, hashed bool) (map[string]user.SessionState, error) {
	result := make(map[string]user.SessionState)
	if len(keyNames) == 0 {
		return result, nil
	}

	if hashed {
		prefix := b.store.GetKeyPrefix()
		prefixedKeys := make([]string, len(keyNames))
		for i, keyName := range keyNames {
			prefixedKeys[i] = prefix + keyName
		}

		jsonValues, err := b.store.GetRawMultiKey(prefixedKeys)
		if err != nil {
			log.WithError(err).Debug("Failed to bulk fetch hashed sessions")
			return nil, err
		}

		for i, jsonVal := range jsonValues {
			if jsonVal == "" {
				continue
			}
			session := &user.SessionState{}
			if err := json.Unmarshal([]byte(jsonVal), session); err != nil {
				log.WithField("key", keyNames[i]).Error("Failed to unmarshal session in bulk fetch")
				continue
			}
			session.KeyID = keyNames[i]
			result[keyNames[i]] = *session
		}
		return result, nil
	}

	allKeysToSearch := make([]string, 0, len(keyNames)*2)
	searchToOriginal := make(map[string]string)

	for _, keyName := range keyNames {
		if storage.TokenOrg(keyName) != orgID {
			if !b.Gw.GetConfig().DisableKeyActionsByUsername {
				legacyKey := b.Gw.generateToken(orgID, keyName)
				allKeysToSearch = append(allKeysToSearch, legacyKey)
				searchToOriginal[legacyKey] = keyName
			}
			allKeysToSearch = append(allKeysToSearch, keyName)
			searchToOriginal[keyName] = keyName

			for _, fallback := range b.Gw.GetConfig().HashKeyFunctionFallback {
				if !b.Gw.GetConfig().DisableKeyActionsByUsername {
					fallbackKey := b.Gw.generateToken(orgID, keyName, fallback)
					allKeysToSearch = append(allKeysToSearch, fallbackKey)
					searchToOriginal[fallbackKey] = keyName
				}
			}
		} else {
			allKeysToSearch = append(allKeysToSearch, keyName)
			searchToOriginal[keyName] = keyName
		}
	}

	jsonValues, err := b.store.GetMultiKey(allKeysToSearch)
	if err != nil {
		log.WithError(err).Debug("Failed to bulk fetch legacy sessions")
		return nil, err
	}

	for i, jsonVal := range jsonValues {
		if jsonVal == "" {
			continue
		}
		foundKey := allKeysToSearch[i]
		originalKey := searchToOriginal[foundKey]

		if _, exists := result[originalKey]; exists {
			continue
		}

		session := &user.SessionState{}
		if err := json.Unmarshal([]byte(jsonVal), session); err != nil {
			log.WithField("key", foundKey).WithError(err).Error("Failed to unmarshal session in bulk fetch")
			continue
		}
		session.KeyID = foundKey
		result[originalKey] = *session
	}

	return result, nil
}

func (b *DefaultSessionManager) Stop() {}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(filter string) []string {
	return b.store.GetKeys(filter)
}

type DefaultKeyGenerator struct {
	Gw *Gateway `json:"-"`
}

func (gw *Gateway) generateToken(orgID, keyID string, customHashKeyFunction ...string) string {
	keyID = strings.TrimPrefix(keyID, orgID)
	hashKeyFunction := gw.GetConfig().HashKeyFunction

	if len(customHashKeyFunction) > 0 {
		hashKeyFunction = customHashKeyFunction[0]
	}

	token, err := storage.GenerateToken(orgID, keyID, hashKeyFunction)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "auth-mgr",
			"orgID":  orgID,
		}).WithError(err).Warning("Issue during token generation")
	}

	return token
}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (d DefaultKeyGenerator) GenerateAuthKey(orgID string) string {
	return d.Gw.generateToken(orgID, "")
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateHMACSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.NewHex()))
}
