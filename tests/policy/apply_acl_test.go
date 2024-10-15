package policy

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
)

type ApplyPolicyFunc func(*user.SessionState) error

func testApplyPolicyFn(t *testing.T) ApplyPolicyFunc {
	bmid := &BaseMiddleware{
		Spec: &APISpec{
			APIDefinition: &apidef.APIDefinition{},
		},
		Gw: &Gateway{},
	}
	return bmid.ApplyPolicies
}

func TestApplyACL_FromCustomPolicies(t *testing.T) {
	applyPolicy := testApplyPolicyFn(t)

	pol1 := user.Policy{
		ID:         "pol1",
		Partitions: user.PolicyPartitions{RateLimit: true},
		Rate:       8,
		Per:        1,
		AccessRights: map[string]user.AccessDefinition{
			"a": {},
		},
	}

	pol2 := user.Policy{
		ID:         "pol2",
		Partitions: user.PolicyPartitions{Acl: true},
		Rate:       10,
		Per:        1,
		AccessRights: map[string]user.AccessDefinition{
			"a": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"GET", "POST"}},
					{URL: "/companies", Methods: []string{"GET", "POST"}},
				},
			},
		},
	}

	t.Run("RateLimit first", func(t *testing.T) {
		session := &user.SessionState{}
		session.SetCustomPolicies([]user.Policy{pol1, pol2})

		assert.NoError(t, applyPolicy(session))
		assert.Equal(t, pol2.AccessRights["a"].AllowedURLs, session.AccessRights["a"].AllowedURLs)
		assert.Equal(t, 8, int(session.Rate))
	})

	t.Run("ACL first", func(t *testing.T) {
		session := &user.SessionState{}
		session.SetCustomPolicies([]user.Policy{pol2, pol1})

		assert.NoError(t, applyPolicy(session))
		assert.Equal(t, pol2.AccessRights["a"].AllowedURLs, session.AccessRights["a"].AllowedURLs)
		assert.Equal(t, 8, int(session.Rate))
	})
}
