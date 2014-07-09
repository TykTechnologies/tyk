package main

import (
	"encoding/json"
	"time"
)

// AuthorisationHandler is used to validate a session key,
// implementing IsKeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	IsKeyAuthorised(string) (bool, SessionState)
	IsKeyExpired(SessionState) bool
}

// AuthorisationManager implements AuthorisationHandler,
// requires a StorageHandler to interact with key store
type AuthorisationManager struct {
	Store StorageHandler
}

// IsKeyAuthorised checks if key exists and can be read into a SessionState object
func (b AuthorisationManager) IsKeyAuthorised(keyName string) (bool, SessionState) {
	jsonKeyVal, err := b.Store.GetKey(keyName)
	var newSession SessionState
	if err != nil {
		log.Warning("Invalid key detected, not found in storage engine")
		return false, newSession
	} else {
		err := json.Unmarshal([]byte(jsonKeyVal), &newSession)
		if err != nil {
			log.Error("Couldn't unmarshal session object")
			log.Error(err)
			return false, newSession
		} else {
			return true, newSession
		}
	}
}

func (b AuthorisationManager) IsKeyExpired(newSession *SessionState) bool {
	if newSession.Expires >= 1 {
		diff := newSession.Expires - time.Now().Unix()
		if diff > 0 {
			return false
		} else {
			return true
		}
	} else {
		return false
	}
}

// UpdateSession updates the session state in the storage engine
func (b AuthorisationManager) UpdateSession(keyName string, session SessionState) {
	v, _ := json.Marshal(session)
	log.Info(session)
	key_exp := (session.Expires - time.Now().Unix()) + 300 // Add 5 minutes to key expiry, just in case

	b.Store.SetKey(keyName, string(v), key_exp)
}

func (b AuthorisationManager) GetSessionDetail(keyName string) (SessionState, bool) {
	jsonKeyVal, err := b.Store.GetKey(keyName)
	var thisSession SessionState
	if err != nil {
		log.Warning("Key does not exist")
		return thisSession, false
	} else {
		err := json.Unmarshal([]byte(jsonKeyVal), &thisSession)
		if err != nil {
			log.Error("Couldn't unmarshal session object")
			log.Error(err)
			return thisSession, false
		} else {
			return thisSession, true
		}
	}
}

func (b AuthorisationManager) GetSessions(filter string) []string {
	return b.Store.GetKeys(filter)
}
