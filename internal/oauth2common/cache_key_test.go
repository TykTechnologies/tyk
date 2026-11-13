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

func TestCacheKey_DifferentIssuers(t *testing.T) {
	// A "sub" is only unique within its issuer. One provider can list several
	// issuers, so the same sub from two issuers must not share a cache entry.
	k1 := CacheKeyInput{Issuer: "https://idp-a", SubjectID: "alice", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	k2 := CacheKeyInput{Issuer: "https://idp-b", SubjectID: "alice", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}
	assert.NotEqual(t, k1.Build(), k2.Build())
}

func TestCacheKey_TenantEndpoint(t *testing.T) {
	base := CacheKeyInput{
		Issuer: "https://one-issuer", SubjectID: "user-1", APIID: "api",
		Audience: "api://orders", Scopes: []string{"read"}, ProviderName: "p",
	}

	t.Run("different tenant endpoints yield different keys", func(t *testing.T) {
		a, b := base, base
		a.TenantEndpoint = "https://idp/tenant-a/token"
		b.TenantEndpoint = "https://idp/tenant-b/token"
		assert.NotEqual(t, a.Build(), b.Build())
	})

	t.Run("empty tenant endpoint leaves the key unchanged", func(t *testing.T) {
		withField := base
		withField.TenantEndpoint = ""
		assert.Equal(t, base.Build(), withField.Build())
	})
}

func TestCacheKey_Resources(t *testing.T) {
	base := CacheKeyInput{
		Issuer: "https://idp", SubjectID: "user-1", APIID: "api1",
		Audience: "https://orders.example.com", Scopes: []string{"write", "read"}, ProviderName: "p",
	}

	t.Run("no resources keeps the key computed before the field existed", func(t *testing.T) {
		assert.Equal(t, "oauth2:exchange:890aa8eec73de554541d23be43fe6309229178f52806e5850a7b000bbd5ae83b", base.Build())
	})

	t.Run("different resources yield different keys", func(t *testing.T) {
		a, b := base, base
		a.Resources = []string{"https://r1"}
		b.Resources = []string{"https://r2"}
		assert.NotEqual(t, a.Build(), b.Build())
		assert.NotEqual(t, base.Build(), a.Build())
	})

	t.Run("resource order does not matter", func(t *testing.T) {
		a, b := base, base
		a.Resources = []string{"https://r1", "https://r2"}
		b.Resources = []string{"https://r2", "https://r1"}
		assert.Equal(t, a.Build(), b.Build())
	})

	t.Run("resources cannot collide with a tenant endpoint", func(t *testing.T) {
		a, b := base, base
		a.TenantEndpoint = "https://r1"
		b.Resources = []string{"https://r1"}
		assert.NotEqual(t, a.Build(), b.Build())
	})
}
