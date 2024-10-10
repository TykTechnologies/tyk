package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

func TestMergeAllowedURLs(t *testing.T) {
	svc := &policy.Service{}

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
