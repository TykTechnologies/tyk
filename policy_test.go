package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

func TestLoadPoliciesFromDashboardReLogin(t *testing.T) {
	// Mock Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()

	globalConf := config.Global()
	oldUseDBAppConfigs := globalConf.UseDBAppConfigs
	globalConf.UseDBAppConfigs = false
	config.SetGlobal(globalConf)

	defer func() {
		globalConf.UseDBAppConfigs = oldUseDBAppConfigs
		config.SetGlobal(globalConf)
	}()

	allowExplicitPolicyID := config.Global().Policies.AllowExplicitPolicyID

	policyMap := LoadPoliciesFromDashboard(ts.URL, "", allowExplicitPolicyID)

	if policyMap != nil {
		t.Error("Should be nil because got back 403 from Dashboard")
	}
}

type dummySessionManager struct {
	DefaultSessionManager
}

func (*dummySessionManager) UpdateSession(key string, sess *user.SessionState, ttl int64, hashed bool) error {
	return nil
}

type testApplyPoliciesData struct {
	name      string
	policies  []string
	errMatch  string                               // substring
	sessMatch func(*testing.T, *user.SessionState) // ignored if nil
}

func testPrepareApplyPolicies() (*BaseMiddleware, []testApplyPoliciesData) {
	policiesMu.RLock()
	policiesByID = map[string]user.Policy{
		"nonpart1": {},
		"nonpart2": {},
		"difforg":  {OrgID: "different"},
		"tags1": {
			Partitions: user.PolicyPartitions{Quota: true},
			Tags:       []string{"tagA"},
		},
		"tags2": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Tags:       []string{"tagX", "tagY"},
		},
		"inactive1": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			IsInactive: true,
		},
		"inactive2": {
			Partitions: user.PolicyPartitions{Quota: true},
			IsInactive: true,
		},
		"quota1": {
			Partitions: user.PolicyPartitions{Quota: true},
			QuotaMax:   2,
		},
		"quota2": {Partitions: user.PolicyPartitions{Quota: true}},
		"rate1": {
			Partitions: user.PolicyPartitions{RateLimit: true},
			Rate:       3,
		},
		"rate2": {Partitions: user.PolicyPartitions{RateLimit: true}},
		"acl1": {
			Partitions:   user.PolicyPartitions{Acl: true},
			AccessRights: map[string]user.AccessDefinition{"a": {}},
		},
		"acl2": {
			Partitions:   user.PolicyPartitions{Acl: true},
			AccessRights: map[string]user.AccessDefinition{"b": {}},
		},
		"acl3": {
			AccessRights: map[string]user.AccessDefinition{"c": {}},
		},
	}
	policiesMu.RUnlock()
	bmid := &BaseMiddleware{Spec: &APISpec{
		APIDefinition:  &apidef.APIDefinition{},
		SessionManager: &dummySessionManager{},
	}}
	tests := []testApplyPoliciesData{
		{
			"Empty", nil,
			"", nil,
		},
		{
			"Single", []string{"nonpart1"},
			"", nil,
		},
		{
			"Missing", []string{"nonexistent"},
			"not found", nil,
		},
		{
			"DiffOrg", []string{"difforg"},
			"different org", nil,
		},
		{
			"MultiNonPart", []string{"nonpart1", "nonpart2"},
			"any are non-part", nil,
		},
		{
			"NonpartAndPart", []string{"nonpart1", "quota1"},
			"any are non-part", nil,
		},
		{
			"TagMerge", []string{"tags1", "tags2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := []string{"tagA", "tagX", "tagY"}
				sort.Strings(s.Tags)
				if !reflect.DeepEqual(want, s.Tags) {
					t.Fatalf("want Tags %v, got %v", want, s.Tags)
				}
			},
		},
		{
			"InactiveMergeOne", []string{"tags1", "inactive1"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			},
		},
		{
			"InactiveMergeAll", []string{"inactive1", "inactive2"},
			"", func(t *testing.T, s *user.SessionState) {
				if !s.IsInactive {
					t.Fatalf("want IsInactive to be true")
				}
			},
		},
		{
			"QuotaPart", []string{"quota1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.QuotaMax != 2 {
					t.Fatalf("want QuotaMax to be 2")
				}
			},
		},
		{
			"QuotaParts", []string{"quota1", "quota2"},
			"multiple quota policies", nil,
		},
		{
			"RatePart", []string{"rate1"},
			"", func(t *testing.T, s *user.SessionState) {
				if s.Rate != 3 {
					t.Fatalf("want Rate to be 3")
				}
			},
		},
		{
			"RateParts", []string{"rate1", "rate2"},
			"multiple rate limit policies", nil,
		},
		{
			"AclPart", []string{"acl1"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {}}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			"AclPart", []string{"acl1", "acl2"},
			"", func(t *testing.T, s *user.SessionState) {
				want := map[string]user.AccessDefinition{"a": {}, "b": {}}
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
		{
			"RightsUpdate", []string{"acl3"},
			"", func(t *testing.T, s *user.SessionState) {
				newPolicy := user.Policy{
					AccessRights: map[string]user.AccessDefinition{"a": {}, "b": {}, "c": {}},
				}
				policiesMu.Lock()
				policiesByID["acl3"] = newPolicy
				policiesMu.Unlock()
				err := bmid.ApplyPolicies("", s)
				if err != nil {
					t.Fatalf("couldn't apply policy: %s", err.Error())
				}
				want := newPolicy.AccessRights
				if !reflect.DeepEqual(want, s.AccessRights) {
					t.Fatalf("want %v got %v", want, s.AccessRights)
				}
			},
		},
	}

	return bmid, tests
}

func TestApplyPolicies(t *testing.T) {
	bmid, tests := testPrepareApplyPolicies()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			errStr := ""
			if err := bmid.ApplyPolicies("", sess); err != nil {
				errStr = err.Error()
			}
			if tc.errMatch == "" && errStr != "" {
				t.Fatalf("didn't want err but got %s", errStr)
			} else if !strings.Contains(errStr, tc.errMatch) {
				t.Fatalf("error %q doesn't match %q",
					errStr, tc.errMatch)
			}
			if tc.sessMatch != nil {
				tc.sessMatch(t, sess)
			}
		})
	}
}

func BenchmarkApplyPolicies(b *testing.B) {
	b.ReportAllocs()

	bmid, tests := testPrepareApplyPolicies()

	for i := 0; i < b.N; i++ {
		for _, tc := range tests {
			sess := &user.SessionState{}
			sess.SetPolicies(tc.policies...)
			bmid.ApplyPolicies("", sess)
		}
	}
}
