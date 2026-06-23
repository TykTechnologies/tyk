package policy_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/policy"
	tyklog "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/user"
)

func TestMergeAllowedURLs(t *testing.T) {
	logger, _ := tyklog.NewNullLogger()

	svc := policy.New(nil, nil, logger)

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
			Options: user.AccessConditionOptions{
				RoutingTriggerOptions: apidef.RoutingTriggerOptions{
					QueryValMatches: map[string]apidef.StringRegexMap{
						param: {MatchPattern: pattern},
					},
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

func TestMergeAllowedURLs_BodyFieldConditions(t *testing.T) {
	condition := func(pattern string) []user.AccessCondition {
		return []user.AccessCondition{{
			On: apidef.All,
			Options: user.AccessConditionOptions{
				BodyFieldMatches: []user.BodyFieldMatch{
					{Path: "customer.id", StringRegexMap: apidef.StringRegexMap{MatchPattern: pattern}},
				},
			},
		}}
	}

	// Specs that differ only by their body field matches must stay separate,
	// or merging would evaluate one policy's rule under the other's methods.
	s1 := []user.AccessSpec{{URL: "/orders", Methods: []string{"GET"}, Conditions: condition("^1$")}}
	s2 := []user.AccessSpec{{URL: "/orders", Methods: []string{"POST"}, Conditions: condition("^2$")}}

	assert.Equal(t, []user.AccessSpec{
		{URL: "/orders", Methods: []string{"GET"}, Conditions: condition("^1$")},
		{URL: "/orders", Methods: []string{"POST"}, Conditions: condition("^2$")},
	}, policy.MergeAllowedURLs(s1, s2))
}

// BenchmarkMergeAllowedURLs measures the cost of merging access specs with and
// without conditions. Specs without conditions are keyed by URL alone and never
// reach the JSON encoding, so the "no conditions" case is what every existing
// deployment pays.
func BenchmarkMergeAllowedURLs(b *testing.B) {
	condition := []user.AccessCondition{{
		On: apidef.All,
		Options: user.AccessConditionOptions{
			RoutingTriggerOptions: apidef.RoutingTriggerOptions{
				QueryValMatches: map[string]apidef.StringRegexMap{
					"persnbr": {MatchPattern: "^[0-9]+$"},
					"account": {Reverse: true},
				},
				HeaderMatches: map[string]apidef.StringRegexMap{
					"X-Tenant": {MatchPattern: "^acme$"},
				},
			},
		},
	}}

	build := func(withConditions bool) []user.AccessSpec {
		specs := make([]user.AccessSpec, 0, 20)
		for i := 0; i < 20; i++ {
			spec := user.AccessSpec{
				URL:     "/resource/" + strconv.Itoa(i),
				Methods: []string{"GET", "POST"},
			}
			if withConditions {
				spec.Conditions = condition
			}
			specs = append(specs, spec)
		}
		return specs
	}

	for _, bc := range []struct {
		name           string
		withConditions bool
	}{
		{name: "no conditions", withConditions: false},
		{name: "with conditions", withConditions: true},
	} {
		s1, s2 := build(bc.withConditions), build(bc.withConditions)

		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = policy.MergeAllowedURLs(s1, s2)
			}
		})
	}
}
