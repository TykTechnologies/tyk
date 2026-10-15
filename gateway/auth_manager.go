package gateway

import (
	"encoding/base64"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/pkg/controlplane/keys"
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
	KeyExpired(newSession *user.SessionState) bool
	Sessions(filter string) []string
	ResetQuota(string, *user.SessionState, bool)
	Stop()
}

// DefaultSessionManager is the gateway's SessionHandler. The persistence
// logic lives in pkg/controlplane/keys.SessionManager; this type binds it to
// the gateway's live configuration, session cache and cluster notifier.
type DefaultSessionManager struct {
	store storage.Handler
	orgID string
	Gw    *Gateway `json:"-"`
}

// manager binds the shared session logic to this gateway instance. The
// returned value is cheap and carries no state beyond the store, so one is
// built per call rather than cached on the struct, which keeps struct
// literal construction (used throughout the gateway and its tests) valid.
func (b *DefaultSessionManager) manager() *keys.SessionManager {
	return keys.NewSessionManager(b.store, b.hashConfig, b.clearCacheForKey, log)
}

func (b *DefaultSessionManager) hashConfig() keys.HashConfig {
	if b.Gw == nil {
		return keys.HashConfig{}
	}
	return hashConfigFromGateway(b.Gw)
}

func hashConfigFromGateway(gw *Gateway) keys.HashConfig {
	c := gw.GetConfig()
	return keys.HashConfig{
		HashKeys:                    c.HashKeys,
		HashKeyFunction:             c.HashKeyFunction,
		HashKeyFunctionFallback:     c.HashKeyFunctionFallback,
		DisableKeyActionsByUsername: c.DisableKeyActionsByUsername,
		EnableKeyLogging:            c.EnableKeyLogging,
	}
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
	return b.manager().KeyExpired(newSession)
}

func (b *DefaultSessionManager) Store() storage.Handler {
	return b.store
}

func (b *DefaultSessionManager) ResetQuota(keyName string, session *user.SessionState, isHashed bool) {
	b.manager().ResetQuota(keyName, session, isHashed)
}

func rawKeysWithAllowanceScope(rawKeys []string, keyName string, session *user.SessionState) []string {
	return keys.RawKeysWithAllowanceScope(rawKeys, keyName, session)
}

func (b *DefaultSessionManager) deleteRawKeysWithAllowanceScope(store storage.Handler, session *user.SessionState, keyName string) {
	keys.DeleteRawKeysWithAllowanceScope(store, session, keyName)
}

// clearCacheForKey is the change hook: it drops the key from this gateway's
// session cache and tells the rest of the cluster to do the same.
func (b *DefaultSessionManager) clearCacheForKey(cacheKey string) {
	if b.Gw == nil {
		return
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
func (b *DefaultSessionManager) UpdateSession(
	keyName string,
	session *user.SessionState,
	resetTTLTo int64,
	hashed bool,
) error {
	return b.manager().UpdateSession(keyName, session, resetTTLTo, hashed)
}

// RemoveSession removes session from storage
func (b *DefaultSessionManager) RemoveSession(orgID string, keyName string, hashed bool) bool {
	return b.manager().RemoveSession(orgID, keyName, hashed)
}

// SessionDetail returns the session detail using the storage engine (either in memory or Redis)
func (b *DefaultSessionManager) SessionDetail(orgID string, keyName string, hashed bool) (user.SessionState, bool) {
	return b.manager().SessionDetail(orgID, keyName, hashed)
}

func (b *DefaultSessionManager) Stop() {}

// Sessions returns all sessions in the key store that match a filter key (a prefix)
func (b *DefaultSessionManager) Sessions(filter string) []string {
	return b.manager().Sessions(filter)
}

type DefaultKeyGenerator struct {
	Gw *Gateway `json:"-"`
}

func (gw *Gateway) generateToken(orgID, keyID string, customHashKeyFunction ...string) string {
	hashKeyFunction := gw.GetConfig().HashKeyFunction
	if len(customHashKeyFunction) > 0 {
		hashKeyFunction = customHashKeyFunction[0]
	}
	return keys.GenerateToken(hashKeyFunction, orgID, keyID, log)
}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (d DefaultKeyGenerator) GenerateAuthKey(orgID string) string {
	return d.Gw.generateToken(orgID, "")
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateHMACSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.NewHex()))
}
