package oauth2common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashActorID_StableAndDistinct(t *testing.T) {
	a := HashActorID("actor-token")
	assert.Equal(t, a, HashActorID("actor-token"), "same input must hash stably")
	assert.NotEqual(t, a, HashActorID("other-token"), "distinct inputs must not collide")
	assert.NotEmpty(t, a)
	// 16 bytes hex-encoded: wide enough that collision search is infeasible for
	// a value an untrusted caller supplies via a request header.
	assert.Len(t, a, 32)
}

func TestActorCacheKey_KeyedOnEndpointClientSecretScopes(t *testing.T) {
	base := ActorCacheKey("https://idp/token", "actor", "secret", []string{"a", "b"})
	assert.Equal(t, base, ActorCacheKey("https://idp/token", "actor", "secret", []string{"b", "a"}),
		"scope order must not change the key")
	assert.NotEqual(t, base, ActorCacheKey("https://idp/token", "other", "secret", []string{"a", "b"}),
		"client id participates in the key")
	assert.NotEqual(t, base, ActorCacheKey("https://other/token", "actor", "secret", []string{"a", "b"}),
		"token endpoint participates in the key")
	assert.NotEqual(t, base, ActorCacheKey("https://idp/token", "actor", "other-secret", []string{"a", "b"}),
		"client secret participates in the key: providers sharing an endpoint and client id but holding different secrets must not share a cached token")
}

func TestActorCacheKey_CarriesNoPlaintextSecret(t *testing.T) {
	key := ActorCacheKey("https://idp/token", "actor", "super-secret-value", nil)
	assert.NotContains(t, key, "super-secret-value",
		"the secret must participate only as a hash so cache keys carry no recoverable credential")
}

func TestActorCacheKey_ScopeEncodingUnambiguous(t *testing.T) {
	// A separator-joined key gives these the same encoding, so the second
	// caller is served the first caller's token for a different scope set.
	assert.NotEqual(t,
		ActorCacheKey("https://idp/token", "actor", "secret", []string{"read,write"}),
		ActorCacheKey("https://idp/token", "actor", "secret", []string{"read", "write"}),
		`["read,write"] and ["read","write"] are distinct scope sets and must not share a key`)

	assert.NotEqual(t,
		ActorCacheKey("https://idp/token", "actor", "secret", []string{"read write"}),
		ActorCacheKey("https://idp/token", "actor", "secret", []string{"read", "write"}),
		"a scope containing a space must not collide with two scopes")

	// A scope set must not be imitable by a neighbouring field's content.
	assert.NotEqual(t,
		ActorCacheKey("https://idp/token", "actor", "secret", []string{"a"}),
		ActorCacheKey("https://idp/token", "actor|1:a", "secret", nil),
		"field contents must not be able to imitate a part boundary")
}

func TestCacheKeyInput_DelegationVsImpersonation(t *testing.T) {
	base := CacheKeyInput{SubjectID: "alice", APIID: "api1", Audience: "aud", Scopes: []string{"r"}, ProviderName: "p"}

	impersonation := base
	impersonation.ActorID = "impersonation"
	delegation := base
	delegation.ActorID = HashActorID("actor-token")

	assert.NotEqual(t, impersonation.Build(), delegation.Build(),
		"delegation and impersonation must not share a cache entry for the same subject/target")
}

// TestCacheKeyInput_NoAmbiguousEncoding covers the exchanged-token cache key.
// Its components are claim-derived, so a value containing the join delimiter
// must not be able to produce another input's key.
func TestCacheKeyInput_NoAmbiguousEncoding(t *testing.T) {
	assert.NotEqual(t,
		CacheKeyInput{Scopes: []string{"read write"}}.Build(),
		CacheKeyInput{Scopes: []string{"read", "write"}}.Build(),
		"a scope containing the scope separator must not collide with two scopes")

	assert.NotEqual(t,
		CacheKeyInput{Issuer: "a|b", SubjectID: "c"}.Build(),
		CacheKeyInput{Issuer: "a", SubjectID: "b|c"}.Build(),
		"a delimiter inside one field must not shift a part boundary")

	assert.NotEqual(t,
		CacheKeyInput{ActorID: "act", TenantEndpoint: "https://t"}.Build(),
		CacheKeyInput{ActorID: "act|https://t"}.Build(),
		"an ActorID containing the delimiter must not imitate a set TenantEndpoint")

	assert.Equal(t,
		CacheKeyInput{Issuer: "iss", SubjectID: "sub"}.Build(),
		CacheKeyInput{Issuer: "iss", SubjectID: "sub", TenantEndpoint: ""}.Build(),
		"sanity: an unset and an explicitly empty TenantEndpoint are the same key")
}

// TestCacheKeyInput_AllFieldsParticipate guards that no component was dropped
// from the key by the encoding change.
func TestCacheKeyInput_AllFieldsParticipate(t *testing.T) {
	base := CacheKeyInput{
		Issuer: "iss", SubjectID: "sub", APIID: "api", Audience: "aud",
		Scopes: []string{"s"}, ProviderName: "prov", TenantEndpoint: "https://t", ActorID: "act",
	}
	for name, mutate := range map[string]func(*CacheKeyInput){
		"Issuer":         func(k *CacheKeyInput) { k.Issuer = "other" },
		"SubjectID":      func(k *CacheKeyInput) { k.SubjectID = "other" },
		"APIID":          func(k *CacheKeyInput) { k.APIID = "other" },
		"Audience":       func(k *CacheKeyInput) { k.Audience = "other" },
		"Scopes":         func(k *CacheKeyInput) { k.Scopes = []string{"other"} },
		"ProviderName":   func(k *CacheKeyInput) { k.ProviderName = "other" },
		"TenantEndpoint": func(k *CacheKeyInput) { k.TenantEndpoint = "https://other" },
		"ActorID":        func(k *CacheKeyInput) { k.ActorID = "other" },
	} {
		changed := base
		mutate(&changed)
		assert.NotEqual(t, base.Build(), changed.Build(), "%s must participate in the cache key", name)
	}

	// Scope order must still not matter.
	reordered := base
	reordered.Scopes = []string{"s"}
	assert.Equal(t, base.Build(), reordered.Build())
	multi := base
	multi.Scopes = []string{"a", "b"}
	multiReordered := base
	multiReordered.Scopes = []string{"b", "a"}
	assert.Equal(t, multi.Build(), multiReordered.Build(), "scope order must not change the key")
}
