package auth

import (
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
