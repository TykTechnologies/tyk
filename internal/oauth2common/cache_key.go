package oauth2common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const cacheKeyPrefix = "oauth2:exchange:"

// CacheKeyInput holds the components of a token exchange cache key.
type CacheKeyInput struct {
	Issuer       string
	SubjectID    string
	APIID        string
	Audience     string
	Scopes       []string
	ProviderName string
	// ActorID discriminates delegation results from impersonation results for
	// the same subject/target. The impersonation sentinel for non-delegated
	// exchanges; the actor client id or a HashActorID otherwise.
	ActorID string
}

// Build returns the cache key for this input as a hex-encoded SHA-256 with the oauth2:exchange: prefix.
func (k CacheKeyInput) Build() string {
	sorted := make([]string, len(k.Scopes))
	copy(sorted, k.Scopes)
	sort.Strings(sorted)
	// Issuer scopes SubjectID: a "sub" is only unique within its issuer.
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		k.Issuer, k.SubjectID, k.APIID, k.Audience,
		strings.Join(sorted, " "), k.ProviderName, k.ActorID)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s%x", cacheKeyPrefix, h)
}

// ActorCacheKey keys a client_credentials actor-token cache entry. Built from
// non-secret operator config (token endpoint + client id + sorted scopes).
func ActorCacheKey(tokenEndpoint, clientID string, scopes []string) string {
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	return tokenEndpoint + "|" + clientID + "|" + strings.Join(sorted, ",")
}

// HashActorID returns a short stable id for a header/static actor token, used
// only as a component of the exchange cache key (never logged). Truncated to
// 8 bytes — full collision resistance isn't required because the subject/target
// tuple already differs in another component.
func HashActorID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8])
}
