package auth

import (
	"github.com/TykTechnologies/tyk/storage"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/session"
	"github.com/TykTechnologies/tyk/session_handler"
)

type DefaultSessionManager struct {
	store storage.StorageHandler
	conf *config.Config
}

func (b *DefaultSessionManager) Init(store storage.StorageHandler, conf *config.Config) {
	b.store = store
	b.conf = conf
	b.store.Connect()
}

func (b *DefaultSessionManager) Store() storage.StorageHandler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, sess *session.SessionState) {
	rawKey := session_handler.QuotaKeyPrefix + PublicHash(keyName, b.conf)
	log.WithFields(logrus.Fields{
		"prefix":      "auth-mgr",
		"inbound-key": ObfuscateKeyString(keyName),
		"key":         rawKey,
	}).Info("Reset quota for key.")

	rateLimiterSentinelKey := session_handler.RateLimitKeyPrefix + PublicHash(keyName, b.conf) + ".BLOCKED"
	// Clear the rate limiter
	go b.store.DeleteRawKey(rateLimiterSentinelKey)
	// Fix the raw key
	go b.store.DeleteRawKey(rawKey)
	//go b.store.SetKey(rawKey, "0", session.QuotaRenewalRate)
}

// UpdateSession updates the session state in the storage engine
func (b *DefaultSessionManager) UpdateSession(keyName string, sess *session.SessionState, resetTTLTo int64) error {
	if !sess.HasChanged() {
		log.Debug("Session has not changed, not updating")
		return nil
	}

	v, _ := json.Marshal(sess)

	// Keep the TTL
	if b.conf.UseAsyncSessionWrite {
		go b.store.SetKey(keyName, string(v), resetTTLTo)
		return nil
	}
	return b.store.SetKey(keyName, string(v), resetTTLTo)
}

func (b *DefaultSessionManager) RemoveSession(keyName string) {
	b.store.DeleteKey(keyName)
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(keyName string) (session.SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(keyName)
	var sess session.SessionState
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix":      "auth-mgr",
			"inbound-key": ObfuscateKeyString(keyName),
			"err":         err,
		}).Debug("Could not get session detail, key not found")
		return sess, false
	}

	if err := json.Unmarshal([]byte(jsonKeyVal), &sess); err != nil {
		log.Error("Couldn't unmarshal session object (may be cache miss): ", err)
		return sess, false
	}

	sess.SetFirstSeenHash()

	return sess, true
}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(filter string) []string {
	return b.store.GetKeys(filter)
}


