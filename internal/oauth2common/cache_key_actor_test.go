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
}

func TestActorCacheKey_KeyedOnEndpointClientScopes(t *testing.T) {
	base := ActorCacheKey("https://idp/token", "actor", []string{"a", "b"})
	assert.Equal(t, base, ActorCacheKey("https://idp/token", "actor", []string{"b", "a"}),
		"scope order must not change the key")
	assert.NotEqual(t, base, ActorCacheKey("https://idp/token", "other", []string{"a", "b"}),
		"client id participates in the key")
	assert.NotEqual(t, base, ActorCacheKey("https://other/token", "actor", []string{"a", "b"}),
		"token endpoint participates in the key")
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
