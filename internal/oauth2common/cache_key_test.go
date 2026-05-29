package oauth2common

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheKey_DifferentSubjectIDs(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "user-a", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "user-b", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_DifferentAudiences(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud-A", Scopes: []string{"r"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud-B", Scopes: []string{"r"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_DifferentScopes(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"read"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"write"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_SameAPIAndAudienceDifferentScopes_TwoEntries(t *testing.T) {
	// Same API + same audience + different per-op scopes must produce different keys.
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud-A", Scopes: []string{"Mail.Read"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud-A", Scopes: []string{"Mail.Read", "Mail.Send"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_ScopesNormalized(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"b", "a"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"a", "b"}, ProviderName: "p"}
	assert.Equal(t, k1.Build(), k2.Build())
}

func TestCacheKey_Prefix(t *testing.T) {
	k := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	assert.True(t, strings.HasPrefix(k.Build(), "oauth2:exchange:"))
}

func TestCacheKey_DifferentProviders(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "provider-a"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "provider-b"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_DifferentAPIIDs(t *testing.T) {
	k1 := CacheKeyInput{SubjectID: "u1", APIID: "api-x", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	k2 := CacheKeyInput{SubjectID: "u1", APIID: "api-y", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}
