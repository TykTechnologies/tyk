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
	// TenantEndpoint is the claim-resolved token endpoint when it differs
	// from the provider's configured one; empty for static endpoints. It
	// keys the cache per tenant for IdPs whose tenants share one issuer.
	TenantEndpoint string
	// ActorID discriminates delegation results from impersonation results for
	// the same subject/target. The impersonation sentinel for non-delegated
	// exchanges; the actor client id or a HashActorID otherwise.
	ActorID string
}

// encodeKeyParts joins parts into one unambiguous string. Each part is written
// as its byte length, a colon, then the part itself, so no part's content can
// imitate a separator or shift a boundary: a plain delimiter-joined key gives
// ["a|b", "c"] and ["a", "b|c"] the same encoding, and length prefixing is what
// keeps distinct inputs mapping to distinct keys.
func encodeKeyParts(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "%d:%s|", len(p), p)
	}
	return b.String()
}

// encodeScopes encodes a scope set order-independently and unambiguously.
// Joining on a separator instead would collide — ["read,write"] and
// ["read", "write"] both flatten to "read,write" — so each scope is length
// prefixed, along with the count.
func encodeScopes(scopes []string) string {
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	return fmt.Sprintf("%d:%s", len(sorted), encodeKeyParts(sorted...))
}

// Build returns the cache key for this input as a hex-encoded SHA-256 with the
// oauth2:exchange: prefix. Every component is length prefixed, so no claim
// value containing a delimiter can produce another input's key.
func (k CacheKeyInput) Build() string {
	// Issuer precedes SubjectID: a "sub" is only unique within its issuer.
	raw := encodeKeyParts(
		k.Issuer, k.SubjectID, k.APIID, k.Audience,
		encodeScopes(k.Scopes), k.ProviderName, k.ActorID, k.TenantEndpoint,
	)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s%x", cacheKeyPrefix, h)
}

// ActorCacheKey keys a client_credentials actor-token cache entry, binding the
// endpoint, client id, client secret and scopes. The secret participates as a
// hash: two providers sharing an endpoint and client id but holding different
// secrets must never share a cached token, and a cache key should carry no
// recoverable credential.
func ActorCacheKey(tokenEndpoint, clientID, clientSecret string, scopes []string) string {
	secret := sha256.Sum256([]byte(clientSecret))
	return encodeKeyParts(
		tokenEndpoint, clientID, hex.EncodeToString(secret[:16]), encodeScopes(scopes),
	)
}

// HashActorID returns a short stable id for a header/static actor token, used
// only as a component of the exchange cache key (never logged). Truncated to
// 16 bytes, which keeps the key compact while leaving collision search
// infeasible for a value an untrusted caller can supply via a request header.
func HashActorID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:16])
}
