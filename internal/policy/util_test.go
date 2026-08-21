package policy_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

func TestMergeAllowedURLs(t *testing.T) {
	svc := policy.New(nil, nil, logrus.New())

	session := &user.SessionState{}
	policies := []user.Policy{
		{
			ID: "pol1",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					AllowedURLs: []user.AccessSpec{
						{URL: "/user", Methods: []string{"GET"}},
						{URL: "/companies", Methods: []string{"GET"}},
					},
				},
			},
		},
		{
			ID: "pol2",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					AllowedURLs: []user.AccessSpec{
						{URL: "/user", Methods: []string{"POST", "PATCH", "PUT"}},
						{URL: "/companies", Methods: []string{"POST"}},
						{URL: "/admin", Methods: []string{"GET", "POST"}},
					},
				},
			},
		},
		{
			ID: "pol3",
			AccessRights: map[string]user.AccessDefinition{
				"a": {
					AllowedURLs: []user.AccessSpec{
						{URL: "/admin/cache", Methods: []string{"DELETE"}},
					},
				},
			},
		},
	}

	session.SetCustomPolicies(policies)

	assert.NoError(t, svc.Apply(session))

	want := []user.AccessSpec{
		{URL: "/user", Methods: []string{"GET", "POST", "PATCH", "PUT"}},
		{URL: "/companies", Methods: []string{"GET", "POST"}},
		{URL: "/admin", Methods: []string{"GET", "POST"}},
		{URL: "/admin/cache", Methods: []string{"DELETE"}},
	}

	assert.Equal(t, want, session.AccessRights["a"].AllowedURLs)
}

func TestMergeAllowedURLs_Conditions(t *testing.T) {
	condition := func(param, pattern string) []user.AccessCondition {
		return []user.AccessCondition{{
			On: apidef.All,
			Options: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{
					param: {MatchPattern: pattern},
				},
			},
		}}
	}

	s1 := []user.AccessSpec{
		{URL: "/user", Methods: []string{"GET"}, Conditions: condition("region", "^eu$")},
		{URL: "/companies", Methods: []string{"GET"}},
	}
	s2 := []user.AccessSpec{
		// Same URL, different condition: has to stay a separate entry so it is
		// evaluated on its own, otherwise merging two policies would grant less
		// than either did alone.
		{URL: "/user", Methods: []string{"POST"}, Conditions: condition("region", "^us$")},
		// Same URL and same condition: methods merge as usual.
		{URL: "/user", Methods: []string{"DELETE"}, Conditions: condition("region", "^eu$")},
		// Same URL without conditions is distinct from the conditioned ones.
		{URL: "/user", Methods: []string{"HEAD"}},
		{URL: "/companies", Methods: []string{"POST"}},
	}

	want := []user.AccessSpec{
		{URL: "/user", Methods: []string{"GET", "DELETE"}, Conditions: condition("region", "^eu$")},
		{URL: "/companies", Methods: []string{"GET", "POST"}},
		{URL: "/user", Methods: []string{"POST"}, Conditions: condition("region", "^us$")},
		{URL: "/user", Methods: []string{"HEAD"}},
	}

	assert.Equal(t, want, policy.MergeAllowedURLs(s1, s2))
}
