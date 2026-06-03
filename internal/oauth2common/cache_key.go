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
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s%x", cacheKeyPrefix, h)
}
