package policy_test

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

//go:embed testdata/*.json
var testDataFS embed.FS

func TestApplyRateLimits_PolicyLimits(t *testing.T) {
	svc := &policy.Service{}

	t.Run("policy limits unset", func(t *testing.T) {
		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 10,
				Per:  10,
			},
		}
		policy := user.Policy{}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 5, int(session.Rate))
	})

	t.Run("policy limits apply all", func(t *testing.T) {
		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 5,
				Per:  10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 10, int(session.Rate))
	})

	// As the policy defined a higher rate than apiLimits,
	// changes are applied to api limits, but skipped on
	// the session as the session has a higher allowance.
	t.Run("policy limits apply per-api", func(t *testing.T) {
		session := &user.SessionState{
			Rate: 15,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{
				Rate: 5,
				Per:  10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 10, int(apiLimits.Rate))
		assert.Equal(t, 15, int(session.Rate))
	})

	// As the policy defined a lower rate than apiLimits,
	// no changes to api limits are applied.
	t.Run("policy limits skip", func(t *testing.T) {
		session := &user.SessionState{
			Rate: 5,
			Per:  10,
		}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 15,
				Per: 10,
			},
		}
		policy := user.Policy{
			Rate: 10,
			Per:  10,
		}

		svc.ApplyRateLimits(session, policy, &apiLimits)

		assert.Equal(t, 15, int(apiLimits.Rate))
		assert.Equal(t, 10, int(session.Rate))
	})
}

func TestApplyRateLimits_FromCustomPolicies(t *testing.T) {
	svc := &policy.Service{}

	t.Run("Custom policies", func(t *testing.T) {
		session := &user.SessionState{}
		session.SetCustomPolicies([]user.Policy{
			{
				ID:           "pol1",
				Partitions:   user.PolicyPartitions{RateLimit: true},
				Rate:         8,
				Per:          1,
				AccessRights: map[string]user.AccessDefinition{"a": {}},
			},
			{
				ID:           "pol2",
				Partitions:   user.PolicyPartitions{RateLimit: true},
				Rate:         10,
				Per:          1,
				AccessRights: map[string]user.AccessDefinition{"a": {}},
			},
		})

		svc.Apply(session)

		assert.Equal(t, 10, int(session.Rate))
	})
}

func TestApplyEndpointLevelLimits(t *testing.T) {
	f, err := testDataFS.ReadFile("testdata/apply_endpoint_rl.json")
	assert.NoError(t, err)

	var testCases []struct {
		Name     string         `json:"name"`
		PolicyEP user.Endpoints `json:"policyEP"`
		CurrEP   user.Endpoints `json:"currEP"`
		Expected user.Endpoints `json:"expected"`
	}
	err = json.Unmarshal(f, &testCases)
	assert.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			service := policy.Service{}
			result := service.ApplyEndpointLevelLimits(tc.PolicyEP, tc.CurrEP)
			assert.ElementsMatch(t, tc.Expected, result)
		})
	}

}
