package main

// Returns the lifetime (TTL) for a session object for storage, not token expiry
func getLifetime(spec *APISpec, session *SessionState) int64 {
	if globalConf.ForceGlobalSessionLifetime {
		return globalConf.GlobalSessionLifetime
	}
	if session.SessionLifetime > 0 {
		return session.SessionLifetime
	}
	if spec.SessionLifetime > 0 {
		return spec.SessionLifetime
	}
	return 0
}
