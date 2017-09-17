package auth

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/spaolacci/murmur3"
	"encoding/hex"
	"github.com/TykTechnologies/tyk/session"
)

// Returns the lifetime (TTL) for a session object for storage, not token expiry
func GetLifetime(spec *apidef.APIDefinition, ses *session.SessionState, conf *config.Config) int64 {
	if conf.ForceGlobalSessionLifetime {
		return conf.GlobalSessionLifetime
	}
	if ses.SessionLifetime > 0 {
		return ses.SessionLifetime
	}
	if spec.SessionLifetime > 0 {
		return spec.SessionLifetime
	}
	return 0
}

func DoHash(in string) string {
	h := murmur3.New32()
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

//Public function for use in classes that bypass elements of the storage manager
func PublicHash(in string, conf *config.Config) string {
	if !conf.HashKeys {
		// Not hashing? Return the raw key
		return in
	}

	return DoHash(in)
}