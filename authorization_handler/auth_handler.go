package authorization_handler

import (
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/session"
)

// AuthorisationHandler is used to validate a session key,
// implementing IsKeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	Init(storage.StorageHandler)
	IsKeyAuthorised(string) (session.SessionState, bool)
	IsKeyExpired(*session.SessionState) bool
}
