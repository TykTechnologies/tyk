package oauth2common

import (
	"crypto/sha256"
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
	// RequestedTokenType is the provider's configured requested_token_type,
	// empty when none is configured. It keeps a cached token of
	// one type from being served after the provider is reconfigured to ask for
	// another.
	RequestedTokenType string
}

// Build returns the cache key for this input as a hex-encoded SHA-256 with the oauth2:exchange: prefix.
func (k CacheKeyInput) Build() string {
	sorted := make([]string, len(k.Scopes))
	copy(sorted, k.Scopes)
	sort.Strings(sorted)
	// Issuer scopes SubjectID: a "sub" is only unique within its issuer.
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		k.Issuer, k.SubjectID, k.APIID, k.Audience,
		strings.Join(sorted, " "), k.ProviderName)
	// Appended only when set so keys for static-endpoint providers are
	// unchanged by the field's introduction.
	if k.TenantEndpoint != "" {
		raw += "|" + k.TenantEndpoint
	}
	// Same rule: providers without one keep their existing keys. The
	// "rtt=" tag keeps it distinct from a TenantEndpoint in the same slot.
	if k.RequestedTokenType != "" {
		raw += "|rtt=" + k.RequestedTokenType
	}
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s%x", cacheKeyPrefix, h)
}
