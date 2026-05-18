// Phase: bug-hunt — fuzz targets for policy engine arithmetic, comparison, and input handling.
//
// These targets exercise the internal (unexported) functions that fuzz testing
// from package policy_test cannot reach: applyAPILevelLimits, simpleFieldWrite,
// greaterThanInt64, greaterThanInt, and the full Apply pipeline with storage.

package policy

import (
	"math"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
)

// ---------------------------------------------------------------------------
// FuzzGreaterThanInt64
// ---------------------------------------------------------------------------
// Exercises the sentinel -1 (unlimited) handling and finite ordering with
// edge int64 values: MaxInt64, MinInt64, -1, 0, and everything between.
func FuzzGreaterThanInt64(f *testing.F) {
	seeds := [][2]int64{
		{-1, 0},                // sentinel wins
		{0, -1},                // sentinel blocks
		{-1, -1},               // both sentinel
		{math.MaxInt64, 0},     // max finite
		{0, math.MaxInt64},
		{math.MinInt64, 0},     // min finite
		{0, math.MinInt64},
		{math.MaxInt64, math.MinInt64},
		{math.MinInt64, math.MaxInt64},
		{0, 0},
		{1, 0},
		{0, 1},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, first, second int64) {
		// greaterThanInt64 should never panic for any int64 inputs.
		_ = greaterThanInt64(first, second)
	})
}

// ---------------------------------------------------------------------------
// FuzzGreaterThanInt
// ---------------------------------------------------------------------------
func FuzzGreaterThanInt(f *testing.F) {
	seeds := [][2]int{
		{-1, 0},
		{0, -1},
		{-1, -1},
		{math.MaxInt, 0},
		{0, math.MaxInt},
		{math.MinInt, 0},
		{0, math.MinInt},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, first, second int) {
		_ = greaterThanInt(first, second)
	})
}

// ---------------------------------------------------------------------------
// FuzzSimpleFieldWrite
// ---------------------------------------------------------------------------
// Writes a random int64 into AccessDefinition.Limit.QuotaMax.
// The Z3 lemma assumes v >= 0; we fuzz negative v to find callers that
// bypass the precondition.
func FuzzSimpleFieldWrite(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(-1))
	f.Add(int64(math.MaxInt64))
	f.Add(int64(math.MinInt64))

	f.Fuzz(func(t *testing.T, v int64) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("simpleFieldWrite panicked with v=%d: %v", v, r)
			}
		}()
		ad := user.AccessDefinition{}
		result := simpleFieldWrite(ad, v)
		_ = result
	})
}

// ---------------------------------------------------------------------------
// FuzzApplyAPILevelLimits
// ---------------------------------------------------------------------------
// Exercises applyAPILevelLimits with random AccessDefinition pairs.
// This function does float64 rate/per arithmetic (Duration()), int64
// comparison (greaterThanInt64), and negative-sentinel handling.  It is the
// most arithmetic-dense function in the Apply pipeline.
func FuzzApplyAPILevelLimits(f *testing.F) {
	type row struct {
		pQmax, pQrate int64
		pRate, pPer   float64
		cQmax, cQrate int64
		cRate, cPer   float64
	}
	seeds := []row{
		{math.MaxInt64, 1000, 100, 60, 500, 500, 50, 60},
		{math.MinInt64, 0, 0, 0, 0, 0, 0, 0},
		{-1, 3600, 100, 60, 1000, 3600, 50, 60},
		{-100, -50, -10, -5, -200, -25, -20, -10},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{100, 100, 1e300, 1e-300, 200, 200, 1e-300, 1e300},
	}
	for _, s := range seeds {
		f.Add(s.pQmax, s.pQrate, s.pRate, s.pPer, s.cQmax, s.cQrate, s.cRate, s.cPer)
	}

	svc := &Service{}

	f.Fuzz(func(t *testing.T,
		policyQuotaMax, policyQuotaRenewalRate int64,
		policyRate, policyPer float64,
		currQuotaMax, currQuotaRenewalRate int64,
		currRate, currPer float64) {

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("applyAPILevelLimits panicked: %v", r)
			}
		}()

		policyAD := user.AccessDefinition{
			Limit: user.APILimit{
				RateLimit:        user.RateLimit{Rate: policyRate, Per: policyPer},
				QuotaMax:         policyQuotaMax,
				QuotaRenewalRate: policyQuotaRenewalRate,
			},
		}
		currAD := user.AccessDefinition{
			Limit: user.APILimit{
				RateLimit:        user.RateLimit{Rate: currRate, Per: currPer},
				QuotaMax:         currQuotaMax,
				QuotaRenewalRate: currQuotaRenewalRate,
			},
		}

		result := svc.applyAPILevelLimits(policyAD, currAD)

		// Invariant 1: unlimited quota forces zero renewal rate.
		if result.Limit.QuotaMax == -1 && result.Limit.QuotaRenewalRate != 0 {
			t.Errorf("QuotaMax=-1 (unlimited) should force QuotaRenewalRate=0, got %d",
				result.Limit.QuotaRenewalRate)
		}

		// Invariant 2: nil smoothing shouldn't cause a nil pointer dereference later.
		_ = result.Limit.Smoothing
	})
}

// ---------------------------------------------------------------------------
// FuzzApplyRateLimits
// ---------------------------------------------------------------------------
// Fuzzes ApplyRateLimits with random float64 Rate/Per triples (session,
// policy, apiLimit).  Rate limit arithmetic is float64-heavy and delegates
// to Duration() which converts to time.Duration(int64), creating a float64→
// int64 conversion edge that can produce implementation-defined values for
// Inf/NaN/very-large inputs.
func FuzzApplyRateLimits(f *testing.F) {
	type row struct {
		sRate, sPer, pRate, pPer, aRate, aPer float64
	}
	seeds := []row{
		{0, 0, 0, 0, 0, 0},
		{100, 60, 200, 60, 50, 60},
		{-1, 60, -100, 60, 0, 0},
		{math.MaxFloat64, math.MaxFloat64, math.SmallestNonzeroFloat64, math.SmallestNonzeroFloat64, 0, 0},
		{1e300, 1e-300, 1e-300, 1e300, 1e200, 1e200},
	}
	for _, s := range seeds {
		f.Add(s.sRate, s.sPer, s.pRate, s.pPer, s.aRate, s.aPer)
	}

	svc := &Service{}

	f.Fuzz(func(t *testing.T, sessionRate, sessionPer, policyRate, policyPer, apiLimitRate, apiLimitPer float64) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ApplyRateLimits panicked: %v", r)
			}
		}()

		session := &user.SessionState{
			Rate: sessionRate,
			Per:  sessionPer,
		}
		policyObj := user.Policy{
			Rate: policyRate,
			Per:  policyPer,
		}
		apiLimits := &user.APILimit{
			RateLimit: user.RateLimit{
				Rate: apiLimitRate,
				Per:  apiLimitPer,
			},
		}

		svc.ApplyRateLimits(session, policyObj, apiLimits)
	})
}

// ---------------------------------------------------------------------------
// FuzzApplyMain — full Apply pipeline with storage-backed policies
// ---------------------------------------------------------------------------
// Exercises ClearSession -> policy lookup -> applyPerAPI/applyPartitions.
// Random policy and session values exercise the full comparison and
// assignment code paths.
func FuzzApplyMain(f *testing.F) {
	type row struct {
		pRate, pPer                  float64
		pQmax, pQrate                int64
		sRate, sPer                  float64
		sQmax                        int64
	}
	seeds := []row{
		{100, 60, 5000, 3600, 0, 0, 0},
		{0, 0, -1, 0, 50, 60, 100},
		{-100, -60, -5000, -3600, 0, 0, 0},
		{1e300, 1e-300, math.MaxInt64, math.MaxInt64, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0},
	}
	for _, s := range seeds {
		f.Add(s.pRate, s.pPer, s.pQmax, s.pQrate, s.sRate, s.sPer, s.sQmax)
	}

	f.Fuzz(func(t *testing.T,
		polRate, polPer float64,
		polQuotaMax, polQuotaRenewalRate int64,
		sessionRate, sessionPer float64,
		sessionQuotaMax int64) {

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Apply (main) panicked: %v", r)
			}
		}()

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)
		orgID := "org1"

		pol := user.Policy{
			ID:               "pol1",
			OrgID:            orgID,
			Rate:             polRate,
			Per:              polPer,
			QuotaMax:         polQuotaMax,
			QuotaRenewalRate: polQuotaRenewalRate,
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}

		store := NewStoreMap(map[string]user.Policy{"pol1": pol})
		svc := New(&orgID, store, logger)

		session := &user.SessionState{
			Rate:     sessionRate,
			Per:      sessionPer,
			QuotaMax: sessionQuotaMax,
			MetaData: map[string]interface{}{},
		}
		session.SetPolicies("pol1")

		_ = svc.Apply(session)
	})
}

// ---------------------------------------------------------------------------
// FuzzApplyPartition — full Apply pipeline with partition-based policies
// ---------------------------------------------------------------------------
// Partition policies exercise a different branch: the per-API loops vs.
// session-level fields, and the usePartitions flag toggles which fields
// are copied.
func FuzzApplyPartition(f *testing.F) {
	type row struct {
		pRate, pPer            float64
		pQmax, pQrate          int64
		usePartitions          bool
	}
	seeds := []row{
		{100, 60, 5000, 3600, false},
		{0, 0, -1, 0, true},
		{-100, -60, -5000, -3600, false},
		{1e300, 1e-300, math.MaxInt64, math.MaxInt64, true},
	}
	for _, s := range seeds {
		f.Add(s.pRate, s.pPer, s.pQmax, s.pQrate, s.usePartitions)
	}

	f.Fuzz(func(t *testing.T,
		polRate, polPer float64,
		polQuotaMax, polQuotaRenewalRate int64,
		usePartitions bool) {

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Apply (partition) panicked: %v", r)
			}
		}()

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)
		orgID := "org1"

		pol := user.Policy{
			ID:               "pol1",
			OrgID:            orgID,
			Rate:             polRate,
			Per:              polPer,
			QuotaMax:         polQuotaMax,
			QuotaRenewalRate: polQuotaRenewalRate,
			Partitions: user.PolicyPartitions{
				Acl:       true,
				Quota:     usePartitions,
				RateLimit: !usePartitions,
			},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {Versions: []string{"v1"}},
			},
		}

		store := NewStoreMap(map[string]user.Policy{"pol1": pol})
		svc := New(&orgID, store, logger)

		session := &user.SessionState{
			MetaData: map[string]interface{}{},
		}
		session.SetPolicies("pol1")

		_ = svc.Apply(session)
	})
}

// ---------------------------------------------------------------------------
// FuzzApplyPerAPI — Exercise the per-API branch (Partitions.PerAPI = true)
// ---------------------------------------------------------------------------
func FuzzApplyPerAPI(f *testing.F) {
	seeds := []struct {
		pRate, pPer float64
		pQmax, pQrate int64
	}{
		{100, 60, 5000, 3600},
		{0, 0, 0, 0},
		{-100, -60, -5000, -3600},
		{1e300, 1e-300, math.MaxInt64, math.MaxInt64},
	}
	for _, s := range seeds {
		f.Add(s.pRate, s.pPer, s.pQmax, s.pQrate)
	}

	f.Fuzz(func(t *testing.T,
		polRate, polPer float64,
		polQuotaMax, polQuotaRenewalRate int64) {

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Apply (per-api) panicked: %v", r)
			}
		}()

		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)
		orgID := "org1"

		pol := user.Policy{
			ID:               "pol1",
			OrgID:            orgID,
			Rate:             polRate,
			Per:              polPer,
			QuotaMax:         polQuotaMax,
			QuotaRenewalRate: polQuotaRenewalRate,
			Partitions:       user.PolicyPartitions{PerAPI: true},
			AccessRights: map[string]user.AccessDefinition{
				"api1": {
					Versions: []string{"v1"},
					Limit: user.APILimit{
						RateLimit:        user.RateLimit{Rate: polRate, Per: polPer},
						QuotaMax:         polQuotaMax,
						QuotaRenewalRate: polQuotaRenewalRate,
					},
				},
			},
		}

		store := NewStoreMap(map[string]user.Policy{"pol1": pol})
		svc := New(&orgID, store, logger)

		session := &user.SessionState{
			MetaData: map[string]interface{}{},
		}
		session.SetPolicies("pol1")

		_ = svc.Apply(session)
	})
}
