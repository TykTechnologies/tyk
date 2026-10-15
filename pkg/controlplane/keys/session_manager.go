package keys

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const (
	// QuotaKeyPrefix is the Redis prefix of quota counters.
	QuotaKeyPrefix = "quota-"

	// RateLimitKeyPrefix is the Redis prefix of rate limiter keys.
	RateLimitKeyPrefix = rate.LimiterKeyPrefix

	// SentinelRateLimitKeyPostfix is appended to the rate limiting key to form the sentinel key.
	SentinelRateLimitKeyPostfix = ".BLOCKED"
)

// HashConfig is the subset of gateway configuration that decides how keys
// are addressed in Redis and how they are logged. It must match the values
// of every gateway and MDCB sharing the same Redis.
type HashConfig struct {
	HashKeys                    bool
	HashKeyFunction             string
	HashKeyFunctionFallback     []string
	DisableKeyActionsByUsername bool
	EnableKeyLogging            bool
}

// SessionManager persists user.SessionState values in a key store. It is the
// logic behind the gateway's DefaultSessionManager, with the gateway's
// runtime replaced by three injected dependencies: the store, a config
// accessor and an optional change hook.
type SessionManager struct {
	store    storage.Handler
	cfg      func() HashConfig
	onChange func(keyHash string)
	log      *logrus.Logger
}

// NewSessionManager returns a SessionManager over store. cfg is called on
// every operation so callers with live configuration (the gateway) see
// updates; onChange, when non-nil, receives the hash of every key written
// or removed (the gateway uses it to flush caches and notify the cluster).
func NewSessionManager(store storage.Handler, cfg func() HashConfig, onChange func(keyHash string), log *logrus.Logger) *SessionManager {
	if cfg == nil {
		cfg = func() HashConfig { return HashConfig{} }
	}
	if log == nil {
		log = logrus.StandardLogger()
	}
	return &SessionManager{store: store, cfg: cfg, onChange: onChange, log: log}
}

// Init sets the store and connects it.
func (m *SessionManager) Init(store storage.Handler) {
	m.store = store
	m.store.Connect()
}

// Store returns the underlying key store.
func (m *SessionManager) Store() storage.Handler {
	return m.store
}

// Stop is a no-op kept for interface compatibility.
func (m *SessionManager) Stop() {}

// KeyExpired reports whether the session has an expiry in the past. An
// Expires value below 1 means "never".
func (m *SessionManager) KeyExpired(session *user.SessionState) bool {
	if session.Expires >= 1 {
		return time.Now().After(time.Unix(session.Expires, 0))
	}
	return false
}

// GenerateToken builds a token for orgID and keyID with the configured hash
// function. A leading orgID on keyID is stripped first, matching the
// gateway's generateToken.
func (m *SessionManager) GenerateToken(orgID, keyID string, customHashKeyFunction ...string) string {
	hashKeyFunction := m.cfg().HashKeyFunction
	if len(customHashKeyFunction) > 0 {
		hashKeyFunction = customHashKeyFunction[0]
	}
	return GenerateToken(hashKeyFunction, orgID, keyID, m.log)
}

// GenerateToken is the package-level form of SessionManager.GenerateToken.
func GenerateToken(hashKeyFunction, orgID, keyID string, log *logrus.Logger) string {
	keyID = strings.TrimPrefix(keyID, orgID)
	token, err := storage.GenerateToken(orgID, keyID, hashKeyFunction)
	if err != nil && log != nil {
		log.WithFields(logrus.Fields{
			"prefix": "auth-mgr",
			"orgID":  orgID,
		}).WithError(err).Warning("Issue during token generation")
	}
	return token
}

// ObfuscateKey masks a key for logging unless key logging is enabled.
func (m *SessionManager) ObfuscateKey(keyName string) string {
	return ObfuscateKey(keyName, m.cfg().EnableKeyLogging)
}

// ObfuscateKey masks all but the last four characters of keyName unless
// enableKeyLogging is set.
func ObfuscateKey(keyName string, enableKeyLogging bool) string {
	if enableKeyLogging {
		return keyName
	}
	if len(keyName) > 4 {
		return "****" + keyName[len(keyName)-4:]
	}
	return "--"
}

// ResetQuota deletes the quota counters and the rate-limit sentinel of a
// key. keyName is hashed first unless isHashed is set.
func (m *SessionManager) ResetQuota(keyName string, session *user.SessionState, isHashed bool) {
	cfg := m.cfg()
	origKeyName := keyName

	if !isHashed {
		keyName = storage.HashKey(keyName, cfg.HashKeys)
	}

	rawKey := QuotaKeyPrefix + keyName

	logged := keyName
	if !cfg.HashKeys && !cfg.EnableKeyLogging {
		logged = ObfuscateKey(keyName, false)
	}
	m.log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": ObfuscateKey(origKeyName, cfg.EnableKeyLogging),
		"key":         logged,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := RateLimitKeyPrefix + keyName + SentinelRateLimitKeyPostfix

	keys := RawKeysWithAllowanceScope([]string{rateLimiterSentinelKey, rawKey}, keyName, session)
	m.store.DeleteRawKeys(keys)
}

// RawKeysWithAllowanceScope appends the per-scope quota keys of the session
// to keys.
func RawKeysWithAllowanceScope(keys []string, keyName string, session *user.SessionState) []string {
	for _, acl := range session.AccessRights {
		if acl.AllowanceScope == "" {
			continue
		}
		keys = append(keys, QuotaKeyPrefix+acl.AllowanceScope+"-"+keyName)
	}
	return keys
}

// DeleteRawKeysWithAllowanceScope deletes the per-scope quota keys of the
// session one by one. Nil arguments are ignored.
func DeleteRawKeysWithAllowanceScope(store storage.Handler, session *user.SessionState, keyName string) {
	if store == nil || session == nil {
		return
	}
	for _, acl := range session.AccessRights {
		if acl.AllowanceScope == "" {
			continue
		}
		store.DeleteRawKey(QuotaKeyPrefix + acl.AllowanceScope + "-" + keyName)
	}
}

func (m *SessionManager) changed(keyName string, hashed bool) {
	if m.onChange == nil {
		return
	}
	cacheKey := keyName
	if !hashed {
		cacheKey = storage.HashKey(keyName, m.cfg().HashKeys)
	}
	m.onChange(cacheKey)
}

// UpdateSession writes the session under keyName with the given TTL
// (seconds; 0 means no expiry). Restored sessions (loaded through
// SessionDetail) are written only if the key still exists, so that an
// update cannot resurrect a key deleted concurrently.
func (m *SessionManager) UpdateSession(keyName string, session *user.SessionState, resetTTLTo int64, hashed bool) error {
	defer m.changed(keyName, hashed)

	v, err := json.Marshal(session)
	if err != nil {
		m.log.Error("Error marshalling session for sync update")
		return err
	}

	if !session.IsRestored() {
		if hashed {
			keyName = m.store.GetKeyPrefix() + keyName
			err = m.store.SetRawKey(keyName, string(v), resetTTLTo)
		} else {
			err = m.store.SetKey(keyName, string(v), resetTTLTo)
		}
	} else {
		if hashed {
			keyName = m.store.GetKeyPrefix() + keyName
			err = m.store.SetRawKeyEx(keyName, string(v), resetTTLTo)
		} else {
			err = m.store.SetKeyEx(keyName, string(v), resetTTLTo)
		}
	}

	return err
}

// RemoveSession deletes the session. For raw keys both the legacy and the
// org-prefixed form are removed.
func (m *SessionManager) RemoveSession(orgID string, keyName string, hashed bool) bool {
	defer m.changed(keyName, hashed)

	if hashed {
		return m.store.DeleteRawKey(m.store.GetKeyPrefix() + keyName)
	}
	// support both old and new key hashing
	res1 := m.store.DeleteKey(keyName)
	res2 := m.store.DeleteKey(m.GenerateToken(orgID, keyName))
	return res1 || res2
}

// SessionDetail loads a session by raw key, hash or (for custom keys)
// org-prefixed form, trying the configured fallback hash functions.
func (m *SessionManager) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	cfg := m.cfg()
	var jsonKeyVal string
	var err error
	keyID := keyName

	if hashed {
		jsonKeyVal, err = m.store.GetRawKey(m.store.GetKeyPrefix() + keyName)
	} else {
		if storage.TokenOrg(keyName) != orgID {
			// try to get legacy and new format key at once
			toSearchList := []string{}
			if !cfg.DisableKeyActionsByUsername {
				toSearchList = append(toSearchList, m.GenerateToken(orgID, keyName))
			}

			toSearchList = append(toSearchList, keyName)
			for _, fallback := range cfg.HashKeyFunctionFallback {
				if !cfg.DisableKeyActionsByUsername {
					toSearchList = append(toSearchList, m.GenerateToken(orgID, keyName, fallback))
				}
			}

			var jsonKeyValList []string
			jsonKeyValList, err = m.store.GetMultiKey(toSearchList)
			// pick the 1st non empty from the returned list
			for idx, val := range jsonKeyValList {
				if val != "" {
					jsonKeyVal = val
					keyID = toSearchList[idx]
					break
				}
			}
		} else {
			// key is not an imported one
			jsonKeyVal, err = m.store.GetKey(keyName)
		}
	}

	if err != nil {
		m.log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKey(keyName, cfg.EnableKeyLogging),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return user.SessionState{}, false
	}
	session := &user.SessionState{}
	if err := json.Unmarshal([]byte(jsonKeyVal), &session); err != nil {
		m.log.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return user.SessionState{}, false
	}
	session.KeyID = keyID
	session.MarkAsRestored()
	return session.Clone(), true
}

// Sessions returns the keys in the store matching the filter prefix.
func (m *SessionManager) Sessions(filter string) []string {
	return m.store.GetKeys(filter)
}
