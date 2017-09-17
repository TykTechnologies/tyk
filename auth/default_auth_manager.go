package auth

import (
	"github.com/TykTechnologies/tyk/storage"
	"time"
	"github.com/Sirupsen/logrus"
	"encoding/json"
	"github.com/TykTechnologies/tyk/session"
	logger "github.com/TykTechnologies/tyk/log"
)

// DefaultAuthorisationManager implements AuthorisationHandler,
// requires a StorageHandler to interact with key store
type DefaultAuthorisationManager struct {
	store storage.StorageHandler
}

var log = logger.Get()

func (b *DefaultAuthorisationManager) Init(store storage.StorageHandler) {
	b.store = store
	b.store.Connect()
}

// IsKeyAuthorised checks if key exists and can be read into a SessionState object
func (b *DefaultAuthorisationManager) IsKeyAuthorised(keyName string) (session.SessionState, bool) {
	jsonKeyVal, err := b.store.GetKey(keyName)
	var newSession session.SessionState
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

// IsKeyExpired checks if a key has expired, if the value of SessionState.Expires is 0, it will be ignored
func (b *DefaultAuthorisationManager) IsKeyExpired(newSession *session.SessionState) bool {
	if newSession.Expires >= 1 {
		return time.Now().After(time.Unix(newSession.Expires, 0))
	}
	return false
}