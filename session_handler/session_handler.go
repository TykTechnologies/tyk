package session_handler

import (
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/session"
)

const (
	QuotaKeyPrefix     = "quota-"
	RateLimitKeyPrefix = "rate-limit-"
)

// SessionHandler handles all update/create/access session functions and deals exclusively with
// SessionState objects, not identity
type SessionHandler interface {
	Init(store storage.StorageHandler, conf *config.Config)
	UpdateSession(keyName string, session *session.SessionState, resetTTLTo int64) error
	RemoveSession(keyName string)
	SessionDetail(keyName string) (session.SessionState, bool)
	Sessions(filter string) []string
	Store() storage.StorageHandler
	ResetQuota(string, *session.SessionState)
}