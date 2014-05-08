package main

import (
	"encoding/json"
)

// AuthorisationHandler is used to validate a session key,
// implementing IsKeyAuthorised() to validate if a key exists or
// is valid in any way (e.g. cryptographic signing etc.). Returns
// a SessionState object (deserialised JSON)
type AuthorisationHandler interface {
	IsKeyAuthorised(string) (bool, SessionState)
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

// UpdateSession updates the session state in the storage engine
func (b AuthorisationManager) UpdateSession(keyName string, session SessionState) {
	v, _ := json.Marshal(session)
	b.Store.SetKey(keyName, string(v))
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

func (b AuthorisationManager) GetSessions() []string {
	return b.Store.GetKeys()
}
