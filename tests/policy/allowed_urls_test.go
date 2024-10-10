package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// The integration test.
func TestAllowedURLs(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	policyBase := user.Policy{
		ID:               uuid.New(),
		Per:              1,
		Rate:             1000,
		QuotaMax:         50,
		QuotaRenewalRate: 3600,
		OrgID:            DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
				Limit: user.APILimit{
					QuotaMax:         100,
					QuotaRenewalRate: 3600,
					RateLimit: user.RateLimit{
						Rate: 1000,
						Per:  1,
					},
				},
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"GET"}},
					{URL: "/companies", Methods: []string{"GET"}},
				},
			},
			"api2": {
				Versions: []string{"v1"},
				Limit: user.APILimit{
					QuotaMax:         200,
					QuotaRenewalRate: 3600,
					RateLimit: user.RateLimit{
						Rate: 1000,
						Per:  1,
					},
				},
				AllowedURLs: []user.AccessSpec{
					{URL: "/user", Methods: []string{"POST", "PATCH", "PUT"}},
					{URL: "/companies", Methods: []string{"POST"}},
					{URL: "/admin", Methods: []string{"GET", "POST"}},
				},
			},
			"api3": {
				Versions: []string{"v1"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/admin/cache", Methods: []string{"DELETE"}},
				},
			},
		},
	}

	policyWithPaths := user.Policy{
		ID:               uuid.New(),
		Per:              1,
		Rate:             1000,
		QuotaMax:         50,
		QuotaRenewalRate: 3600,
		OrgID:            DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				Versions: []string{"v1"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/appended", Methods: []string{"GET"}},
				},
			},
			"api2": {
				Versions: []string{"v1"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/appended", Methods: []string{"GET"}},
				},
			},
			"api3": {
				Versions: []string{"v1"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/appended", Methods: []string{"GET"}},
				},
			},
		},
	}

	ts.Gw.SetPoliciesByID(policyBase, policyWithPaths)

	// load APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Name = "api 1"
			spec.APIID = "api1"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api1"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 2"
			spec.APIID = "api2"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api2"
			spec.OrgID = DefaultOrg
		},
		func(spec *APISpec) {
			spec.Name = "api 3"
			spec.APIID = "api3"
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/api3"
			spec.OrgID = DefaultOrg
		},
	)

	// create test session
	session := &user.SessionState{
		ApplyPolicies: []string{policyBase.ID, policyWithPaths.ID},
		OrgID:         DefaultOrg,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				APIID:    "api1",
				Versions: []string{"v1"},
			},
			"api2": {
				APIID:    "api2",
				Versions: []string{"v1"},
			},
			"api3": {
				APIID:    "api3",
				Versions: []string{"v1"},
			},
		},
	}

	// create key
	key := uuid.New()
	ts.Run(t, test.TestCase{Method: http.MethodPost, Path: "/tyk/keys/" + key, Data: session, AdminAuth: true, Code: 200})

	// check key session
	t.Run("Check key session", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method:    http.MethodGet,
				Path:      fmt.Sprintf("/tyk/keys/%v?org_id=%v", key, DefaultOrg),
				AdminAuth: true,
				Code:      http.StatusOK,
				BodyMatchFunc: func(data []byte) bool {
					session := user.SessionState{}
					assert.NoError(t, json.Unmarshal(data, &session))

					for _, apiName := range []string{"api1", "api2", "api3"} {
						want := policy.MergeAllowedURLs(policyBase.AccessRights[apiName].AllowedURLs, policyWithPaths.AccessRights[apiName].AllowedURLs)
						assert.Equal(t, want, session.AccessRights[apiName].AllowedURLs, fmt.Sprintf("api %q allowed urls don't match", apiName))
					}

					return true
				},
			},
		}...)
	})
}
