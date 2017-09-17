package main

import "github.com/TykTechnologies/tyk/auth"

// Returns the lifetime (TTL) for a session object for storage, not token expiry
func getLifetime(spec *APISpec, session *SessionState) int64 {
	return auth.GetLifetime(spec.APIDefinition, session, &globalConf)
}

