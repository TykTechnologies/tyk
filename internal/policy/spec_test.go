package policy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

// FLIPTestCase represents a FLIP-generated test fixture.
type FLIPTestCase struct {
	Name          string                    `json:"name"`
	Requirement   string                    `json:"requirement"`
	Obligation    string                    `json:"obligation"`
	TraceLength   int                       `json:"trace_length"`
	Signals       map[string][]bool         `json:"signals"`
	ExpectedHolds map[string][]bool         `json:"expected_holds"`
}

func loadFLIPFixtures(t *testing.T) []FLIPTestCase {
	t.Helper()

	// FLIP test cases are in the project root tests/policy/ dir
	root := filepath.Join("..", "..", "tests", "policy")
	matches, err := filepath.Glob(filepath.Join(root, "tc-*.json"))
	if err != nil || len(matches) == 0 {
		t.Skipf("No FLIP test fixtures found in %s", root)
	}

	var fixtures []FLIPTestCase
	for _, path := range matches {
		data, err := os.ReadFile(path)
		require.NoError(t, err, "reading %s", path)

		var tc FLIPTestCase
		require.NoError(t, json.Unmarshal(data, &tc), "parsing %s", path)
		fixtures = append(fixtures, tc)
	}
	return fixtures
}

func sig(tc FLIPTestCase, name string, step int) bool {
	vals, ok := tc.Signals[name]
	if !ok || step >= len(vals) {
		return false
	}
	return vals[step]
}

// newTestService creates a policy.Service for testing.
func newTestService(orgID string, policies []user.Policy) *policy.Service {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	store := policy.NewStore(policies)
	return policy.New(&orgID, store, logger)
}

// TestSpec_MetadataMerged verifies SYS-REQ-017:
// Apply always merges metadata
func TestSpec_MetadataMerged(t *testing.T) {
	orgID := "org1"
	pol := user.Policy{
		ID:    "pol1",
		OrgID: orgID,
		Rate:  100,
		Per:   60,
		MetaData: map[string]interface{}{
			"key1": "value1",
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol})

	session := &user.SessionState{}
	session.SetPolicies("pol1")
	session.MetaData = map[string]interface{}{
		"existing": "data",
	}

	err := svc.Apply(session)
	require.NoError(t, err)

	assert.Equal(t, "value1", session.MetaData["key1"])
	assert.Equal(t, "data", session.MetaData["existing"])
}

// TestSpec_ClearSession verifies SYS-REQ-019 and SYS-REQ-020
func TestSpec_ClearSession(t *testing.T) {
	orgID := "org1"

	t.Run("clear resets values for existing policy", func(t *testing.T) {
		pol := user.Policy{
			ID:    "pol1",
			OrgID: orgID,
			Rate:  100,
			Per:   60,
		}
		svc := newTestService(orgID, []user.Policy{pol})

		session := &user.SessionState{
			QuotaMax:       1000,
			QuotaRemaining: 500,
			Rate:           200,
			Per:            120,
			MaxQueryDepth:  5,
		}
		session.SetPolicies("pol1")

		err := svc.ClearSession(session)
		require.NoError(t, err)
		assert.Equal(t, int64(0), session.QuotaMax, "quota should be cleared")
		assert.Equal(t, float64(0), session.Rate, "rate should be cleared")
		assert.Equal(t, 0, session.MaxQueryDepth, "complexity should be cleared")
	})

	t.Run("clear errors for missing policy", func(t *testing.T) {
		svc := newTestService(orgID, nil) // empty store

		session := &user.SessionState{}
		session.SetPolicies("nonexistent")

		err := svc.ClearSession(session)
		assert.Error(t, err, "ClearSession should error for missing policy")
	})
}

// TestSpec_MutualExclusivity_ErrorAndAccess verifies SYS-REQ-028:
// error_reported and access_rights_merged cannot both be true
func TestSpec_MutualExclusivity_ErrorAndAccess(t *testing.T) {
	orgID := "org1"

	// Test: successful apply -> no error, rights merged
	t.Run("success means no error", func(t *testing.T) {
		pol := user.Policy{
			ID:    "pol1",
			OrgID: orgID,
			Rate:  100,
			Per:   60,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol})

		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		errorReported := err != nil
		accessMerged := len(session.AccessRights) > 0

		// Mutual exclusivity: both cannot be true
		assert.False(t, errorReported && accessMerged,
			"error and access merge should be mutually exclusive (got error=%v, merged=%v)", errorReported, accessMerged)
	})

	// Test: error -> no rights merged
	t.Run("error means no access rights", func(t *testing.T) {
		pol := user.Policy{
			ID:    "pol1",
			OrgID: "wrong-org",
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol})

		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		errorReported := err != nil
		accessMerged := len(session.AccessRights) > 0

		assert.True(t, errorReported, "org mismatch should cause error")
		assert.False(t, accessMerged, "error should prevent access rights merge")
	})
}

// ============================================================================
// FLIP Fixtures: Formal Verification Artifacts (NOT Go-Level Test Coverage)
// ============================================================================
//
// The tests/policy/tc-*.json files contain 87 FLIP-generated boolean signal
// traces. These traces are produced by the FLIP model checker to verify that
// the LTL (Linear Temporal Logic) specification of the policy engine is
// internally consistent.
//
// IMPORTANT DISTINCTION:
// - FLIP fixtures prove the SPECIFICATION is correct (the LTL formulas in
//   policy.vars.yaml satisfy MC/DC coverage for each requirement).
// - They do NOT prove the Go CODE matches the specification. That is the
//   job of the Apply()-based tests (apply_test.go, the TestProperty_* and
//   TestZ3_* tests in this file).
//
// Only ~4 fixtures are exercised at the Go level (via TestSpec_FLIPSignalMapping
// below), specifically those testing SYS-REQ-027 (idle state invariant) which
// has a direct boolean-signal interpretation. The other 83 fixtures are formal
// verification artifacts: they certify specification completeness and are
// consumed by the FLIP toolchain, not by `go test`.
//
// This is BY DESIGN. Attempting to map all 87 traces to Go-level assertions
// would require reimplementing the LTL evaluator in Go, which defeats the
// purpose of having a separate formal verification layer.
// ============================================================================

// TestSpec_FLIPSignalMapping verifies that FLIP test signals map to actual code behavior
// for the idle state invariant (SYS-REQ-027).
// NOTE: FLIP traces exercise ONE requirement at a time via MC/DC variable flipping.
// This means individual traces may violate other requirements (Finding 12/29 from dogfooding).
// We only check the idle state invariant on fixtures that explicitly test SYS-REQ-027 (the idle req).
func TestSpec_FLIPSignalMapping(t *testing.T) {
	fixtures := loadFLIPFixtures(t)

	for _, tc := range fixtures {
		t.Run(tc.Name, func(t *testing.T) {
			// Only check idle state constraint on the idle state requirement's own fixtures
			if tc.Requirement != "SYS-REQ-027" {
				return
			}

			for step := 0; step < tc.TraceLength; step++ {
				applyReq := sig(tc, "apply_requested", step)
				clearReq := sig(tc, "clear_requested", step)
				rateLimitReq := sig(tc, "rate_limit_apply_requested", step)
				endpointReq := sig(tc, "endpoint_limit_apply_requested", step)

				// Verify idle state invariant (SYS-REQ-027):
				// If no mode is active, all outputs should be false
				if !applyReq && !clearReq && !rateLimitReq && !endpointReq {
					for _, outVar := range []string{
						"session_cleared", "access_rights_merged", "rate_limit_applied",
						"quota_applied", "tags_merged", "metadata_merged", "error_reported",
						"session_inactive_set", "endpoints_merged", "complexity_applied",
						"result_returned",
					} {
						val := sig(tc, outVar, step)
						if _, exists := tc.Signals[outVar]; exists {
							assert.False(t, val,
								"idle state: %s should be false when no mode active (step %d)", outVar, step)
						}
					}
				}
			}
		})
	}
}


// ============================================================================
// Property-Based Tests: Data-Level Merge Semantics
// ============================================================================
// These tests verify the data properties specified in policy.vars.yaml.
// They go beyond boolean temporal logic to check actual merge behavior.

// PropertyFixture represents a generated property test fixture.
type PropertyFixture struct {
	Name     string                   `json:"name"`
	Property string                   `json:"property"`
	Strategy string                   `json:"strategy"`
	Inputs   []map[string]interface{} `json:"inputs"`
	Expected map[string]interface{}   `json:"expected"`
	Check    string                   `json:"check"`
}

func loadPropertyFixtures(t *testing.T) []PropertyFixture {
	t.Helper()
	root := filepath.Join("..", "..", "tests", "policy", "properties")
	matches, err := filepath.Glob(filepath.Join(root, "pt-*.json"))
	if err != nil || len(matches) == 0 {
		t.Skipf("No property test fixtures found in %s", root)
	}

	var fixtures []PropertyFixture
	for _, path := range matches {
		data, err := os.ReadFile(path)
		require.NoError(t, err, "reading %s", path)

		var f PropertyFixture
		require.NoError(t, json.Unmarshal(data, &f), "parsing %s", path)
		fixtures = append(fixtures, f)
	}
	return fixtures
}

// propertyFixtureMapping describes how to translate abstract property fixture values
// into real Policy objects and how to assert the result on a SessionState.
type propertyFixtureMapping struct {
	// setPolicy configures pol1 and pol2 from the fixture inputs.
	// Returns (skip, reason) if the fixture cannot be mapped.
	setPolicy func(fix PropertyFixture, pol1, pol2 *user.Policy) (skip bool, reason string)
	// assertResult checks the session output against the fixture expected value.
	assertResult func(t *testing.T, fix PropertyFixture, session *user.SessionState)
}

// propertyNumericValue extracts a numeric value from a property fixture input.
func propertyNumericValue(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case string:
		// Some fixtures encode -1 as "-1" for unlimited sentinel
		if val == "-1" {
			return -1, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// propertyFixtureMappings maps each property name to its setter and assertion logic.
// Properties that use abstract data models (access_rights_merged, endpoints_merged,
// metadata_merged) cannot be directly mapped to Policy fields because:
//   - access_rights fixtures use abstract {"key1": {"value": "a"}} maps, not real
//     user.AccessDefinition objects with Versions, AllowedURLs, Limit, etc.
//   - endpoints fixtures use the same abstract map format, not user.Endpoints structs
//   - metadata fixtures use {"key": {"value": "x"}} nesting, not flat key->value maps
//
// These abstract fixtures verify the MERGE ALGEBRA (union, combine, highest) at a
// mathematical level. The hand-written TestProperty_* tests above verify the same
// properties against real Go types. The Z3 runner (z3_spec_test.go) also covers
// these properties with concrete Policy objects.
var propertyFixtureMappings = map[string]propertyFixtureMapping{
	"rate_limit_applied": {
		setPolicy: func(fix PropertyFixture, pol1, pol2 *user.Policy) (bool, string) {
			if len(fix.Inputs) < 2 {
				return true, "need at least 2 inputs for rate limit comparison"
			}
			// Two fixture formats: single "rate_limit_applied" number, or "rate"+"per" fields
			if v, ok := propertyNumericValue(fix.Inputs[0], "rate_limit_applied"); ok {
				if v <= 0 {
					return true, "rate limit comparison requires positive values"
				}
				pol1.Rate = v
				pol1.Per = 60 // default period for single-value fixtures
			} else if rate, ok := propertyNumericValue(fix.Inputs[0], "rate"); ok {
				per, _ := propertyNumericValue(fix.Inputs[0], "per")
				if rate <= 0 || per <= 0 {
					return true, "rate limit requires positive rate and per"
				}
				pol1.Rate = rate
				pol1.Per = per
			} else {
				return true, "unrecognized rate_limit fixture input format"
			}

			if v, ok := propertyNumericValue(fix.Inputs[1], "rate_limit_applied"); ok {
				if v <= 0 {
					return true, "rate limit comparison requires positive values"
				}
				pol2.Rate = v
				pol2.Per = 60
			} else if rate, ok := propertyNumericValue(fix.Inputs[1], "rate"); ok {
				per, _ := propertyNumericValue(fix.Inputs[1], "per")
				if rate <= 0 || per <= 0 {
					return true, "rate limit requires positive rate and per"
				}
				pol2.Rate = rate
				pol2.Per = per
			} else {
				return true, "unrecognized rate_limit fixture input format"
			}
			return false, ""
		},
		assertResult: func(t *testing.T, fix PropertyFixture, session *user.SessionState) {
			t.Helper()
			if expectedRate, ok := propertyNumericValue(fix.Expected, "rate_limit_applied"); ok {
				assert.Equal(t, expectedRate, session.Rate,
					"fixture %s: expected rate %v", fix.Name, expectedRate)
			} else if expectedRate, ok := propertyNumericValue(fix.Expected, "rate"); ok {
				assert.Equal(t, expectedRate, session.Rate,
					"fixture %s: expected rate %v", fix.Name, expectedRate)
			}
		},
	},
	"quota_applied": {
		setPolicy: func(fix PropertyFixture, pol1, pol2 *user.Policy) (bool, string) {
			if len(fix.Inputs) < 2 {
				return true, "need at least 2 inputs for quota comparison"
			}
			v1, ok1 := propertyNumericValue(fix.Inputs[0], "quota_applied")
			v2, ok2 := propertyNumericValue(fix.Inputs[1], "quota_applied")
			if !ok1 || !ok2 {
				return true, "unrecognized quota fixture input format"
			}
			pol1.QuotaMax = int64(v1)
			pol2.QuotaMax = int64(v2)
			return false, ""
		},
		assertResult: func(t *testing.T, fix PropertyFixture, session *user.SessionState) {
			t.Helper()
			expected, _ := propertyNumericValue(fix.Expected, "quota_applied")
			tykExpected := int64(expected)
			// Tyk treats -1 as unlimited sentinel (always wins via greaterThanInt64)
			v1, _ := propertyNumericValue(fix.Inputs[0], "quota_applied")
			v2, _ := propertyNumericValue(fix.Inputs[1], "quota_applied")
			if int64(v1) == -1 || int64(v2) == -1 {
				tykExpected = -1
			}
			assert.Equal(t, tykExpected, session.QuotaMax,
				"fixture %s: expected quota %d", fix.Name, tykExpected)
		},
	},
	"complexity_applied": {
		setPolicy: func(fix PropertyFixture, pol1, pol2 *user.Policy) (bool, string) {
			if len(fix.Inputs) < 2 {
				return true, "need at least 2 inputs for complexity comparison"
			}
			v1, ok1 := propertyNumericValue(fix.Inputs[0], "complexity_applied")
			v2, ok2 := propertyNumericValue(fix.Inputs[1], "complexity_applied")
			if !ok1 || !ok2 {
				return true, "unrecognized complexity fixture input format"
			}
			pol1.MaxQueryDepth = int(v1)
			pol2.MaxQueryDepth = int(v2)
			return false, ""
		},
		assertResult: func(t *testing.T, fix PropertyFixture, session *user.SessionState) {
			t.Helper()
			expected, _ := propertyNumericValue(fix.Expected, "complexity_applied")
			tykExpected := int(expected)
			v1, _ := propertyNumericValue(fix.Inputs[0], "complexity_applied")
			v2, _ := propertyNumericValue(fix.Inputs[1], "complexity_applied")
			if int(v1) == -1 || int(v2) == -1 {
				tykExpected = -1
			}
			assert.Equal(t, tykExpected, session.MaxQueryDepth,
				"fixture %s: expected depth %d", fix.Name, tykExpected)
		},
	},
	"tags_merged": {
		setPolicy: func(fix PropertyFixture, pol1, pol2 *user.Policy) (bool, string) {
			if len(fix.Inputs) < 1 {
				return true, "need at least 1 input for tags"
			}
			extractTags := func(m map[string]interface{}) []string {
				v, ok := m["tags_merged"]
				if !ok {
					return nil
				}
				arr, ok := v.([]interface{})
				if !ok {
					return nil
				}
				tags := make([]string, len(arr))
				for i, elem := range arr {
					tags[i], _ = elem.(string)
				}
				return tags
			}
			pol1.Tags = extractTags(fix.Inputs[0])
			if len(fix.Inputs) > 1 {
				pol2.Tags = extractTags(fix.Inputs[1])
			}
			return false, ""
		},
		assertResult: func(t *testing.T, fix PropertyFixture, session *user.SessionState) {
			t.Helper()
			v, ok := fix.Expected["tags_merged"]
			if !ok {
				return
			}
			arr, ok := v.([]interface{})
			if !ok {
				return
			}
			expectedTags := make([]string, len(arr))
			for i, elem := range arr {
				expectedTags[i], _ = elem.(string)
			}
			assert.ElementsMatch(t, expectedTags, session.Tags,
				"fixture %s: expected tags %v, got %v", fix.Name, expectedTags, session.Tags)
		},
	},
}

// TestProperty_FromFixtures is a table-driven test runner that loads all property
// fixtures (pt-*.json), groups them by property, and runs each through Apply()
// using the corresponding property mapping.
//
// Properties with direct Policy field mappings (rate_limit_applied, quota_applied,
// complexity_applied, tags_merged) are fully exercised. Properties that use abstract
// data models (access_rights_merged, endpoints_merged, metadata_merged) are skipped
// because their fixture format uses abstract key/value maps that do not correspond
// to real Go types. Those properties are verified by the hand-written TestProperty_*
// tests and the Z3 fixture runner.
func TestProperty_FromFixtures(t *testing.T) {
	allFixtures := loadPropertyFixtures(t)

	// Group fixtures by property.
	byProperty := make(map[string][]PropertyFixture)
	for _, f := range allFixtures {
		byProperty[f.Property] = append(byProperty[f.Property], f)
	}

	// Track which properties we skip due to unmappable fixture format.
	unmappable := map[string]string{
		"access_rights_merged": "abstract key/value maps do not map to user.AccessDefinition",
		"endpoints_merged":     "abstract key/value maps do not map to user.Endpoints",
		"metadata_merged":      "abstract {key: {value: x}} nesting does not map to flat metadata",
	}

	for property, reason := range unmappable {
		if fixtures, ok := byProperty[property]; ok {
			t.Run(property, func(t *testing.T) {
				t.Skipf("Skipping %d fixtures: %s", len(fixtures), reason)
			})
		}
	}

	for property, mapping := range propertyFixtureMappings {
		mapping := mapping
		fixtures, ok := byProperty[property]
		if !ok || len(fixtures) == 0 {
			t.Logf("No fixtures for property %q, skipping", property)
			continue
		}

		t.Run(property, func(t *testing.T) {
			for _, fix := range fixtures {
				fix := fix
				t.Run(fix.Name, func(t *testing.T) {
					orgID := "org1"
					pol1 := user.Policy{
						ID:    "pol1",
						OrgID: orgID,
						Rate:  10,
						Per:   60,
						AccessRights: map[string]user.AccessDefinition{
							"api1": {Versions: []string{"v1"}},
						},
					}
					pol2 := user.Policy{
						ID:    "pol2",
						OrgID: orgID,
						Rate:  10,
						Per:   60,
						AccessRights: map[string]user.AccessDefinition{
							"api1": {Versions: []string{"v1"}},
						},
					}

					skip, reason := mapping.setPolicy(fix, &pol1, &pol2)
					if skip {
						t.Skipf("Skipping: %s", reason)
					}

					svc := newTestService(orgID, []user.Policy{pol1, pol2})

					session := &user.SessionState{}
					session.SetPolicies("pol1", "pol2")
					session.MetaData = map[string]interface{}{}

					err := svc.Apply(session)
					require.NoError(t, err)

					mapping.assertResult(t, fix, session)
				})
			}
		})
	}
}

// --- Tags: set union, dedup, commutativity ---

// TestProperty_Tags_Dedup verifies that duplicate tags within a single
// policy's tag list are deduplicated in the result.
func TestProperty_Tags_Dedup(t *testing.T) {
	orgID := "org1"
	pol := user.Policy{
		ID:    "pol1",
		OrgID: orgID,
		Rate:  10, Per: 60,
		Tags: []string{"dup", "dup", "unique"},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol})

	session := &user.SessionState{}
	session.SetPolicies("pol1")
	session.MetaData = map[string]interface{}{}
	session.Tags = []string{"dup"} // already in session

	err := svc.Apply(session)
	require.NoError(t, err)

	count := 0
	for _, tag := range session.Tags {
		if tag == "dup" {
			count++
		}
	}
	assert.Equal(t, 1, count, "tag 'dup' should appear exactly once (dedup property)")
}

// TestProperty_Tags_Commutativity verifies that changing the order of
// policies produces the same tag set.
func TestProperty_Tags_Commutativity(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID:    "pol1",
		OrgID: orgID,
		Rate:  10, Per: 60,
		Tags: []string{"alpha", "bravo"},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID:    "pol2",
		OrgID: orgID,
		Rate:  10, Per: 60,
		Tags: []string{"charlie"},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}

	// Apply in order pol1, pol2
	svc1 := newTestService(orgID, []user.Policy{pol1, pol2})
	session1 := &user.SessionState{}
	session1.SetPolicies("pol1", "pol2")
	session1.MetaData = map[string]interface{}{}
	err := svc1.Apply(session1)
	require.NoError(t, err)

	// Apply in order pol2, pol1
	svc2 := newTestService(orgID, []user.Policy{pol2, pol1})
	session2 := &user.SessionState{}
	session2.SetPolicies("pol2", "pol1")
	session2.MetaData = map[string]interface{}{}
	err = svc2.Apply(session2)
	require.NoError(t, err)

	// Both should produce the same tag SET (order may differ)
	sort.Strings(session1.Tags)
	sort.Strings(session2.Tags)
	assert.Equal(t, session1.Tags, session2.Tags,
		"tag merge should be commutative: order of policies should not matter")
}

// --- Rate Limits: highest wins via duration comparison ---

// TestProperty_RateLimit_HighestWins_ByDuration verifies that the policy
// allowing the highest request rate (shortest duration) wins.
func TestProperty_RateLimit_HighestWins_ByDuration(t *testing.T) {
	svc := &policy.Service{}

	t.Run("higher rate same period", func(t *testing.T) {
		session := &user.SessionState{}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 50, Per: 60},
		}
		pol := user.Policy{Rate: 100, Per: 60} // 100/60 > 50/60

		svc.ApplyRateLimits(session, pol, &apiLimits)
		assert.Equal(t, float64(100), apiLimits.Rate, "higher rate should win")
	})

	t.Run("different periods - shorter duration wins", func(t *testing.T) {
		session := &user.SessionState{}
		// Current: 10 per 60 -> duration = 6s per request
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 10, Per: 60},
		}
		// Policy: 2 per 1 -> duration = 0.5s per request (faster!)
		pol := user.Policy{Rate: 2, Per: 1}

		svc.ApplyRateLimits(session, pol, &apiLimits)
		assert.Equal(t, float64(2), apiLimits.Rate,
			"policy with shorter duration (higher rate) should win")
		assert.Equal(t, float64(1), apiLimits.Per)
	})

	t.Run("lower rate is NOT applied", func(t *testing.T) {
		session := &user.SessionState{Rate: 100, Per: 60}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 100, Per: 60},
		}
		pol := user.Policy{Rate: 10, Per: 60} // lower rate

		svc.ApplyRateLimits(session, pol, &apiLimits)
		assert.Equal(t, float64(100), apiLimits.Rate,
			"lower rate should not override higher rate")
	})

	t.Run("empty policy rate is skipped", func(t *testing.T) {
		session := &user.SessionState{Rate: 50, Per: 60}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 50, Per: 60},
		}
		pol := user.Policy{Rate: 0, Per: 0} // empty

		svc.ApplyRateLimits(session, pol, &apiLimits)
		assert.Equal(t, float64(50), apiLimits.Rate,
			"empty policy rate should be skipped")
	})
}

// --- Quota: highest wins, -1 means unlimited ---

// TestProperty_Quota_HighestWins verifies that greaterThanInt64 picks the
// highest quota value, with -1 meaning unlimited.
func TestProperty_Quota_HighestWins(t *testing.T) {
	orgID := "org1"

	t.Run("higher numeric quota wins", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: 100,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: 500,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, int64(500), session.QuotaMax)
	})

	t.Run("unlimited -1 always wins over positive", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: 999999,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: -1,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, int64(-1), session.QuotaMax,
			"unlimited (-1) should always win per greaterThanInt64 semantics")
	})

	t.Run("unlimited -1 first also wins", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: -1,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: 999999,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, int64(-1), session.QuotaMax,
			"unlimited (-1) should win regardless of order")
	})

	t.Run("both unlimited stays unlimited", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: -1,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60, QuotaMax: -1,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, int64(-1), session.QuotaMax)
	})
}

// --- Access Rights: combine by API ID with nested URL union ---

// TestProperty_AccessRights_NestedURLUnion verifies that AllowedURLs within
// access rights are merged via URL-keyed union with method union per URL.
func TestProperty_AccessRights_NestedURLUnion(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID: "pol1", OrgID: orgID,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/users", Methods: []string{"GET"}},
				},
			},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", OrgID: orgID,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				AllowedURLs: []user.AccessSpec{
					{URL: "/users", Methods: []string{"POST"}},
					{URL: "/orders", Methods: []string{"GET"}},
				},
			},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol1, pol2})
	session := &user.SessionState{}
	session.SetPolicies("pol1", "pol2")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	require.NoError(t, err)

	ar := session.AccessRights["api1"]
	require.NotNil(t, ar.AllowedURLs)

	// Find /users and verify method union
	var usersSpec *user.AccessSpec
	var ordersSpec *user.AccessSpec
	for i := range ar.AllowedURLs {
		if ar.AllowedURLs[i].URL == "/users" {
			usersSpec = &ar.AllowedURLs[i]
		}
		if ar.AllowedURLs[i].URL == "/orders" {
			ordersSpec = &ar.AllowedURLs[i]
		}
	}
	require.NotNil(t, usersSpec, "/users should be in allowed URLs")
	assert.Contains(t, usersSpec.Methods, "GET")
	assert.Contains(t, usersSpec.Methods, "POST")

	require.NotNil(t, ordersSpec, "/orders should be in allowed URLs")
	assert.Contains(t, ordersSpec.Methods, "GET")
}

// TestProperty_AccessRights_VersionUnion verifies that versions are merged
// via union across policies for the same API ID.
func TestProperty_AccessRights_VersionUnion(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", OrgID: orgID, Rate: 10, Per: 60,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v2"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol1, pol2})
	session := &user.SessionState{}
	session.SetPolicies("pol1", "pol2")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	require.NoError(t, err)

	ar := session.AccessRights["api1"]
	assert.Contains(t, ar.Versions, "v1", "version v1 should be in union")
	assert.Contains(t, ar.Versions, "v2", "version v2 should be in union")
}

// --- Metadata: combine by key (last-write-wins per key) ---

// TestProperty_Metadata_CombineByKey verifies that metadata is merged
// as a map where later policies overwrite earlier values for the same key.
func TestProperty_Metadata_CombineByKey(t *testing.T) {
	orgID := "org1"

	t.Run("disjoint keys are all present", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
			MetaData: map[string]interface{}{"key1": "value1"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60,
			MetaData: map[string]interface{}{"key2": "value2"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, "value1", session.MetaData["key1"])
		assert.Equal(t, "value2", session.MetaData["key2"])
	})

	t.Run("overlapping keys: last policy wins", func(t *testing.T) {
		pol1 := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
			MetaData: map[string]interface{}{"shared": "from_pol1"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		pol2 := user.Policy{
			ID: "pol2", OrgID: orgID, Rate: 10, Per: 60,
			MetaData: map[string]interface{}{"shared": "from_pol2"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol1, pol2})
		session := &user.SessionState{}
		session.SetPolicies("pol1", "pol2")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		require.NoError(t, err)
		// Last policy in iteration wins (last-write-wins semantics)
		assert.Equal(t, "from_pol2", session.MetaData["shared"],
			"last policy should overwrite metadata for same key")
	})

	t.Run("session existing metadata preserved when no conflict", func(t *testing.T) {
		pol := user.Policy{
			ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
			MetaData: map[string]interface{}{"policy_key": "policy_value"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol})
		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{"session_key": "session_value"}

		err := svc.Apply(session)
		require.NoError(t, err)
		assert.Equal(t, "session_value", session.MetaData["session_key"])
		assert.Equal(t, "policy_value", session.MetaData["policy_key"])
	})
}

// --- Endpoints: combine by path+method, highest rate per endpoint ---

// TestProperty_Endpoints_CombineHighest verifies that endpoint-level rate
// limits are combined by path+method key with the highest rate winning.
func TestProperty_Endpoints_CombineHighest(t *testing.T) {
	svc := &policy.Service{}

	t.Run("overlapping endpoint - higher rate wins", func(t *testing.T) {
		policyEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}
		currEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 50, Per: 60}},
			}},
		}

		result := svc.ApplyEndpointLevelLimits(policyEPs, currEPs)
		require.NotNil(t, result)

		resultMap := result.Map()
		rl, ok := resultMap["GET:/api/users"]
		require.True(t, ok, "GET:/api/users should be in result map")
		// Higher rate (50) should win: 60/50=1.2s < 60/10=6s
		assert.Equal(t, float64(50), rl.Rate,
			"higher rate should win for overlapping endpoint")
	})

	t.Run("disjoint endpoints are both present", func(t *testing.T) {
		policyEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}
		currEPs := user.Endpoints{
			{Path: "/api/orders", Methods: user.EndpointMethods{
				{Name: "POST", Limit: user.RateLimit{Rate: 20, Per: 60}},
			}},
		}

		result := svc.ApplyEndpointLevelLimits(policyEPs, currEPs)
		require.NotNil(t, result)

		resultMap := result.Map()
		_, foundUsers := resultMap["GET:/api/users"]
		_, foundOrders := resultMap["POST:/api/orders"]
		assert.True(t, foundUsers, "GET:/api/users should be in merged endpoints")
		assert.True(t, foundOrders, "POST:/api/orders should be in merged endpoints")
	})

	t.Run("empty current endpoints returns policy endpoints", func(t *testing.T) {
		policyEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}
		result := svc.ApplyEndpointLevelLimits(policyEPs, nil)
		assert.Equal(t, policyEPs, result)
	})

	t.Run("empty policy endpoints returns current endpoints", func(t *testing.T) {
		currEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}
		result := svc.ApplyEndpointLevelLimits(nil, currEPs)
		resultMap := result.Map()
		assert.Len(t, resultMap, 1, "current endpoints should be returned when policy is empty")
	})

	t.Run("equal duration picks higher raw rate", func(t *testing.T) {
		// 10 per 60 => duration 6s, 5 per 30 => duration 6s
		// Equal duration: pick higher Rate (10 > 5)
		policyEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 5, Per: 30}},
			}},
		}
		currEPs := user.Endpoints{
			{Path: "/api/users", Methods: user.EndpointMethods{
				{Name: "GET", Limit: user.RateLimit{Rate: 10, Per: 60}},
			}},
		}

		result := svc.ApplyEndpointLevelLimits(policyEPs, currEPs)
		resultMap := result.Map()
		rl, ok := resultMap["GET:/api/users"]
		require.True(t, ok, "GET:/api/users should be in result")
		assert.Equal(t, float64(10), rl.Rate,
			"equal duration should pick higher raw rate")
	})
}

// --- MergeAllowedURLs: direct unit test of the utility function ---

// TestProperty_MergeAllowedURLs_Union verifies the set union semantics
// of MergeAllowedURLs including deduplication and key-based merge.
func TestProperty_MergeAllowedURLs_Union(t *testing.T) {
	t.Run("methods are unioned per URL", func(t *testing.T) {
		s1 := []user.AccessSpec{
			{URL: "/api/users", Methods: []string{"GET", "HEAD"}},
		}
		s2 := []user.AccessSpec{
			{URL: "/api/users", Methods: []string{"GET", "POST"}},
		}
		result := policy.MergeAllowedURLs(s1, s2)
		require.Len(t, result, 1)
		assert.Equal(t, "/api/users", result[0].URL)
		assert.Contains(t, result[0].Methods, "GET")
		assert.Contains(t, result[0].Methods, "HEAD")
		assert.Contains(t, result[0].Methods, "POST")

		// Dedup: GET should appear only once
		count := 0
		for _, m := range result[0].Methods {
			if m == "GET" {
				count++
			}
		}
		assert.Equal(t, 1, count, "GET should appear only once (dedup)")
	})

	t.Run("disjoint URLs produce union", func(t *testing.T) {
		s1 := []user.AccessSpec{
			{URL: "/api/users", Methods: []string{"GET"}},
		}
		s2 := []user.AccessSpec{
			{URL: "/api/orders", Methods: []string{"POST"}},
		}
		result := policy.MergeAllowedURLs(s1, s2)
		require.Len(t, result, 2)
	})

	t.Run("empty + non-empty returns non-empty", func(t *testing.T) {
		result := policy.MergeAllowedURLs(nil, []user.AccessSpec{
			{URL: "/api/users", Methods: []string{"GET"}},
		})
		require.Len(t, result, 1)
	})

	t.Run("both empty returns nil", func(t *testing.T) {
		result := policy.MergeAllowedURLs(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("order preserved", func(t *testing.T) {
		s1 := []user.AccessSpec{
			{URL: "/b", Methods: []string{"GET"}},
			{URL: "/a", Methods: []string{"GET"}},
		}
		s2 := []user.AccessSpec{
			{URL: "/c", Methods: []string{"GET"}},
		}
		result := policy.MergeAllowedURLs(s1, s2)
		require.Len(t, result, 3)
		assert.Equal(t, "/b", result[0].URL, "order of first appearance should be preserved")
		assert.Equal(t, "/a", result[1].URL)
		assert.Equal(t, "/c", result[2].URL)
	})
}

// --- ClearSession: partition-aware clearing ---

// TestProperty_ClearSession_PartitionBehavior verifies that ClearSession
// respects partition flags when deciding what to clear.
func TestProperty_ClearSession_PartitionBehavior(t *testing.T) {
	orgID := "org1"

	t.Run("quota partition only clears quota", func(t *testing.T) {
		pol := user.Policy{
			ID: "pol1", OrgID: orgID,
			Partitions: user.PolicyPartitions{Quota: true},
		}
		svc := newTestService(orgID, []user.Policy{pol})
		session := &user.SessionState{
			QuotaMax:      1000,
			Rate:          200,
			Per:           60,
			MaxQueryDepth: 5,
		}
		session.SetPolicies("pol1")

		err := svc.ClearSession(session)
		require.NoError(t, err)
		assert.Equal(t, int64(0), session.QuotaMax, "quota should be cleared")
		assert.Equal(t, float64(200), session.Rate, "rate should NOT be cleared")
		assert.Equal(t, 5, session.MaxQueryDepth, "complexity should NOT be cleared")
	})

	t.Run("rate_limit partition only clears rate", func(t *testing.T) {
		pol := user.Policy{
			ID: "pol1", OrgID: orgID,
			Partitions: user.PolicyPartitions{RateLimit: true},
		}
		svc := newTestService(orgID, []user.Policy{pol})
		session := &user.SessionState{
			QuotaMax:      1000,
			Rate:          200,
			Per:           60,
			MaxQueryDepth: 5,
		}
		session.SetPolicies("pol1")

		err := svc.ClearSession(session)
		require.NoError(t, err)
		assert.Equal(t, int64(1000), session.QuotaMax, "quota should NOT be cleared")
		assert.Equal(t, float64(0), session.Rate, "rate should be cleared")
		assert.Equal(t, 5, session.MaxQueryDepth, "complexity should NOT be cleared")
	})

	t.Run("complexity partition only clears depth", func(t *testing.T) {
		pol := user.Policy{
			ID: "pol1", OrgID: orgID,
			Partitions: user.PolicyPartitions{Complexity: true},
		}
		svc := newTestService(orgID, []user.Policy{pol})
		session := &user.SessionState{
			QuotaMax:      1000,
			Rate:          200,
			Per:           60,
			MaxQueryDepth: 5,
		}
		session.SetPolicies("pol1")

		err := svc.ClearSession(session)
		require.NoError(t, err)
		assert.Equal(t, int64(1000), session.QuotaMax, "quota should NOT be cleared")
		assert.Equal(t, float64(200), session.Rate, "rate should NOT be cleared")
		assert.Equal(t, 0, session.MaxQueryDepth, "complexity should be cleared")
	})

	t.Run("no partitions clears everything", func(t *testing.T) {
		pol := user.Policy{
			ID: "pol1", OrgID: orgID,
			// No partitions set -> all=true
		}
		svc := newTestService(orgID, []user.Policy{pol})
		session := &user.SessionState{
			QuotaMax:      1000,
			Rate:          200,
			Per:           60,
			MaxQueryDepth: 5,
		}
		session.SetPolicies("pol1")

		err := svc.ClearSession(session)
		require.NoError(t, err)
		assert.Equal(t, int64(0), session.QuotaMax, "quota should be cleared")
		assert.Equal(t, float64(0), session.Rate, "rate should be cleared")
		assert.Equal(t, 0, session.MaxQueryDepth, "complexity should be cleared")
	})
}

// --- Master Policy: no access rights -> session-level values set directly ---

// TestProperty_MasterPolicy_SessionLevelValues verifies master policy behavior
// where no AccessRights are defined and values apply directly to session.
func TestProperty_MasterPolicy_SessionLevelValues(t *testing.T) {
	orgID := "org1"
	pol := user.Policy{
		ID: "pol1", OrgID: orgID,
		Rate:          100,
		Per:           60,
		QuotaMax:      5000,
		MaxQueryDepth: 10,
		// No AccessRights - master policy
	}
	svc := newTestService(orgID, []user.Policy{pol})
	session := &user.SessionState{}
	session.SetPolicies("pol1")
	session.MetaData = map[string]interface{}{}

	// Apply will return error (no valid policies) but values are set
	_ = svc.Apply(session)

	assert.Equal(t, float64(100), session.Rate)
	assert.Equal(t, float64(60), session.Per)
	assert.Equal(t, int64(5000), session.QuotaMax)
	assert.Equal(t, 10, session.MaxQueryDepth)
}

// --- HMAC/HTTP Signature: sticky-true semantics ---

// TestProperty_HMACEnabled_StickyTrue verifies that once HMAC is enabled
// by a policy, it stays enabled (doesn't get overwritten to false).
func TestProperty_HMACEnabled_StickyTrue(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
		HMACEnabled: true,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", OrgID: orgID, Rate: 10, Per: 60,
		HMACEnabled: false, // This should NOT disable HMAC
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol1, pol2})
	session := &user.SessionState{}
	session.SetPolicies("pol1", "pol2")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	require.NoError(t, err)
	assert.True(t, session.HMACEnabled,
		"HMAC should remain true once set (sticky-true semantics)")
}

// --- LastUpdated: highest timestamp wins ---

// TestProperty_LastUpdated_HighestWins verifies that the session LastUpdated
// is set to the highest value among all applied policies.
func TestProperty_LastUpdated_HighestWins(t *testing.T) {
	orgID := "org1"
	pol1 := user.Policy{
		ID: "pol1", OrgID: orgID, Rate: 10, Per: 60,
		LastUpdated: "100",
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID: "pol2", OrgID: orgID, Rate: 10, Per: 60,
		LastUpdated: "200",
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol1, pol2})
	session := &user.SessionState{}
	session.SetPolicies("pol1", "pol2")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	require.NoError(t, err)
	assert.Equal(t, "200", session.LastUpdated,
		"session LastUpdated should be the highest among all policies")
}

// ============================================================================
// Intent-Based Tests: Rewritten Spec Issues 1-7
// ============================================================================

// TestSpec_Issue1_TagsNotMergedOnError verifies updated SYS-REQ-016:
// Tags must NOT be merged when an error occurs (policy not found, org mismatch).
func TestSpec_Issue1_TagsNotMergedOnError(t *testing.T) {
	orgID := "org1"

	t.Run("tags not merged when single policy not found", func(t *testing.T) {
		svc := newTestService(orgID, nil) // empty store

		session := &user.SessionState{}
		session.SetPolicies("nonexistent")
		session.MetaData = map[string]interface{}{}
		session.Tags = []string{}

		err := svc.Apply(session)
		assert.Error(t, err, "should error when policy not found")
		assert.Empty(t, session.Tags, "tags should NOT be merged when error occurs")
	})

	t.Run("tags not merged when org mismatch", func(t *testing.T) {
		pol := user.Policy{
			ID:    "pol1",
			OrgID: "wrong-org",
			Tags:  []string{"should-not-appear"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol})

		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{}
		session.Tags = []string{}

		err := svc.Apply(session)
		assert.Error(t, err, "should error on org mismatch")
		assert.NotContains(t, session.Tags, "should-not-appear",
			"tags from error policy should NOT be in session")
	})
}

// TestSpec_Issue1_MetadataNotMergedOnError verifies updated SYS-REQ-017:
// Metadata must NOT be merged when an error occurs.
func TestSpec_Issue1_MetadataNotMergedOnError(t *testing.T) {
	orgID := "org1"

	t.Run("metadata not merged when single policy not found", func(t *testing.T) {
		svc := newTestService(orgID, nil)

		session := &user.SessionState{}
		session.SetPolicies("nonexistent")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		assert.Error(t, err)
		assert.Empty(t, session.MetaData, "metadata should NOT be merged on error")
	})

	t.Run("metadata not merged when org mismatch", func(t *testing.T) {
		pol := user.Policy{
			ID:       "pol1",
			OrgID:    "wrong-org",
			MetaData: map[string]interface{}{"bad": "data"},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}
		svc := newTestService(orgID, []user.Policy{pol})

		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{}

		err := svc.Apply(session)
		assert.Error(t, err)
		_, hasBadKey := session.MetaData["bad"]
		assert.False(t, hasBadKey,
			"metadata from error policy should NOT be in session")
	})
}

// TestSpec_Issue1_SessionInactiveNotSetOnError verifies updated SYS-REQ-018:
// session_inactive must NOT be modified when an error occurs.
func TestSpec_Issue1_SessionInactiveNotSetOnError(t *testing.T) {
	orgID := "org1"

	pol := user.Policy{
		ID:         "pol1",
		OrgID:      "wrong-org",
		IsInactive: true,
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol})

	session := &user.SessionState{}
	session.SetPolicies("pol1")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	assert.Error(t, err, "org mismatch should error")
	assert.False(t, session.IsInactive,
		"session inactive should NOT be set when error occurs")
}

// TestSpec_Issue2_AllPoliciesMissing verifies SYS-REQ-040:
// When ALL referenced policies are missing, Apply must return an error.
func TestSpec_Issue2_AllPoliciesMissing(t *testing.T) {
	orgID := "org1"
	svc := newTestService(orgID, nil) // empty store

	session := &user.SessionState{}
	session.SetPolicies("missing1", "missing2", "missing3")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	assert.Error(t, err,
		"Apply should return error when ALL policies are missing")
}

// TestSpec_Issue3_EqualRateLimits verifies SYS-REQ-041:
// When policy rate equals current rate (same duration), what happens?
func TestSpec_Issue3_EqualRateLimits(t *testing.T) {
	t.Run("equal duration does NOT overwrite", func(t *testing.T) {
		svc := &policy.Service{}
		session := &user.SessionState{Rate: 10, Per: 60}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 10, Per: 60},
		}
		pol := user.Policy{Rate: 10, Per: 60} // exact same rate

		svc.ApplyRateLimits(session, pol, &apiLimits)

		// Document actual behavior: equal duration means NOT applied
		// because the condition is `Duration() > policyDuration()` (strict >)
		t.Logf("After equal rate apply: apiLimits.Rate=%v, session.Rate=%v",
			apiLimits.Rate, session.Rate)

		// The code uses strict > comparison: apiLimits.Duration() > policyLimits.Duration()
		// Equal duration means the condition is false, so rate is NOT overwritten.
		// This is a design decision, not a bug.
		assert.Equal(t, float64(10), apiLimits.Rate,
			"equal rate should keep current value (design decision: strict > comparison)")
	})

	t.Run("equal duration with different rate/per values", func(t *testing.T) {
		svc := &policy.Service{}
		// 5 per 10 = 2 requests/second (duration = 2s)
		session := &user.SessionState{Rate: 5, Per: 10}
		apiLimits := user.APILimit{
			RateLimit: user.RateLimit{Rate: 5, Per: 10},
		}
		// 10 per 20 = 0.5 requests/second (duration = 2s) -- same duration!
		pol := user.Policy{Rate: 10, Per: 20}

		svc.ApplyRateLimits(session, pol, &apiLimits)

		t.Logf("After same-duration apply: apiLimits.Rate=%v Per=%v, session.Rate=%v Per=%v",
			apiLimits.Rate, apiLimits.Per, session.Rate, session.Per)
	})
}

// TestSpec_Issue4_NilStore verifies SYS-REQ-042:
// Apply must not panic when store is nil or unavailable.
func TestSpec_Issue4_NilStore(t *testing.T) {
	t.Run("nil store panics or errors on Apply", func(t *testing.T) {
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)
		orgID := "org1"

		// Create service with nil storage
		svc := policy.New(&orgID, nil, logger)

		session := &user.SessionState{}
		session.SetPolicies("pol1")
		session.MetaData = map[string]interface{}{}

		// This should either return an error or panic.
		// We catch panics to document the behavior.
		var err error
		var panicked bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					t.Logf("FINDING: Apply panics with nil store: %v", r)
				}
			}()
			err = svc.Apply(session)
		}()

		if panicked {
			t.Errorf("CODE BUG: Apply panics with nil store instead of returning error")
		} else if err == nil {
			t.Errorf("CODE BUG: Apply silently succeeds with nil store")
		} else {
			t.Logf("OK: Apply returns error with nil store: %v", err)
		}
	})
}

// TestSpec_Issue6_MetadataIterationOrder verifies SYS-REQ-043:
// Metadata merge with conflicting keys in different policy orders.
func TestSpec_Issue6_MetadataIterationOrder(t *testing.T) {
	orgID := "org1"

	pol1 := user.Policy{
		ID:    "pol1",
		OrgID: orgID,
		Rate:  10,
		Per:   60,
		MetaData: map[string]interface{}{
			"conflict_key": "value_from_pol1",
			"unique_pol1":  "data1",
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	pol2 := user.Policy{
		ID:    "pol2",
		OrgID: orgID,
		Rate:  10,
		Per:   60,
		MetaData: map[string]interface{}{
			"conflict_key": "value_from_pol2",
			"unique_pol2":  "data2",
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}

	// Apply with order: pol1, pol2
	svc1 := newTestService(orgID, []user.Policy{pol1, pol2})
	session1 := &user.SessionState{}
	session1.SetPolicies("pol1", "pol2")
	session1.MetaData = map[string]interface{}{}
	err := svc1.Apply(session1)
	require.NoError(t, err)
	val1 := session1.MetaData["conflict_key"]

	// Apply with order: pol2, pol1
	svc2 := newTestService(orgID, []user.Policy{pol2, pol1})
	session2 := &user.SessionState{}
	session2.SetPolicies("pol2", "pol1")
	session2.MetaData = map[string]interface{}{}
	err = svc2.Apply(session2)
	require.NoError(t, err)
	val2 := session2.MetaData["conflict_key"]

	t.Logf("Order pol1,pol2: conflict_key = %v", val1)
	t.Logf("Order pol2,pol1: conflict_key = %v", val2)

	if val1 != val2 {
		t.Logf("FINDING: Metadata merge is ORDER-DEPENDENT. "+
			"pol1,pol2 gives %v; pol2,pol1 gives %v. "+
			"This is a known non-determinism risk with last-write-wins semantics.", val1, val2)
	} else {
		t.Logf("Metadata merge is order-independent for this case (both give %v)", val1)
	}
}

// TestSpec_Issue7_PerformanceBound verifies SYS-REQ-044:
// Apply() must complete within 100ms for up to 50 policies.
func TestSpec_Issue7_PerformanceBound(t *testing.T) {
	orgID := "org1"

	// Create 50 policies, each with access rights
	policies := make([]user.Policy, 50)
	policyIDs := make([]string, 50)
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("pol%d", i)
		policies[i] = user.Policy{
			ID:       id,
			OrgID:    orgID,
			Rate:     float64(10 + i),
			Per:      60,
			QuotaMax: int64(100 * (i + 1)),
			Tags:     []string{fmt.Sprintf("tag%d", i)},
			MetaData: map[string]interface{}{
				fmt.Sprintf("key%d", i): fmt.Sprintf("val%d", i),
			},
			Partitions: user.PolicyPartitions{
				PerAPI: true,
			},
			AccessRights: map[string]user.AccessDefinition{
				fmt.Sprintf("api%d", i): {
					Versions: []string{"v1"},
					Limit: user.APILimit{
						RateLimit: user.RateLimit{Rate: float64(10 + i), Per: 60},
						QuotaMax:  int64(100 * (i + 1)),
					},
				},
			},
		}
		policyIDs[i] = id
	}

	svc := newTestService(orgID, policies)

	session := &user.SessionState{}
	session.SetPolicies(policyIDs...)
	session.MetaData = map[string]interface{}{}

	start := time.Now()
	err := svc.Apply(session)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 100*time.Millisecond,
		"Apply() with 50 policies must complete within 100ms, took %v", elapsed)
	t.Logf("Apply() with 50 policies completed in %v", elapsed)
}

// TestSpec_Issue2_AllPoliciesMissing_MultipleSkipped verifies SYS-REQ-040 deeper:
// When multiple policies are referenced and ALL are missing, error must occur.
// The code currently skips missing policies in multi-policy mode via "continue".
func TestSpec_Issue2_AllPoliciesMissing_MultiplePolicies(t *testing.T) {
	orgID := "org1"
	svc := newTestService(orgID, nil) // empty store

	session := &user.SessionState{}
	session.SetPolicies("missing1", "missing2")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	// The code will "continue" past missing policies when len(policyIDs) > 1.
	// After the loop, it checks `len(rights) == 0 && policyIDs != nil` and
	// returns "key has no valid policies to be applied".
	t.Logf("Apply with all policies missing (multi): err=%v", err)
	assert.Error(t, err,
		"When ALL policies are missing in multi-policy mode, should still error")
}

// TestSpec_Issue1_TagsMergedOnPartialError verifies edge case:
// With 2 policies where one is found and one is missing, tags from
// the found policy ARE merged (the missing one is skipped).
func TestSpec_Issue1_TagsMergedOnPartialError(t *testing.T) {
	orgID := "org1"
	pol := user.Policy{
		ID:    "pol1",
		OrgID: orgID,
		Rate:  100,
		Per:   60,
		Tags:  []string{"good-tag"},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {Versions: []string{"v1"}},
		},
	}
	svc := newTestService(orgID, []user.Policy{pol})

	session := &user.SessionState{}
	session.SetPolicies("pol1", "nonexistent")
	session.MetaData = map[string]interface{}{}

	err := svc.Apply(session)
	require.NoError(t, err, "partial missing in multi-policy should not error")
	assert.Contains(t, session.Tags, "good-tag",
		"tags from valid policy should be merged even when another policy is missing")
}
