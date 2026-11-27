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
	// Resources are the explicit RFC 8707 resource indicators; empty when
	// none is configured, in which case the key is the same as before the
	// field existed.
	Resources []string
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
	if len(k.Resources) > 0 {
		resources := make([]string, len(k.Resources))
		copy(resources, k.Resources)
		sort.Strings(resources)
		raw += "|resources=" + strings.Join(resources, " ")
	}
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s%x", cacheKeyPrefix, h)
}
