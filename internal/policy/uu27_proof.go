// Phase UU.27 — The acid test: lemma on the real applyAPILevelLimits
// method body, lowered end-to-end through the translator.
//
// TRANSLATOR GAP (documented): the real applyAPILevelLimits body uses
// multiple mid-block if-without-else statements whose bodies do not end
// with `return`. The gosmt translator only supports two shapes for `if`:
//
//   (a) early-return: `if cond { return X }` mid-block — the body
//       terminates, so the rest-of-block can serve as the synthetic else.
//   (b) last-statement if-with-else: `if cond { ... } else { ... }` at
//       the end of a block — each branch terminates.
//
// Real production Go code overwhelmingly uses mid-block non-returning
// if bodies (set some state, then fall through). This is a fundamental
// limitation of the pure-functional SMT translation model in its current
// form. A workaround is to express the same logic using the early-return
// pattern, which produces an equivalent ite structure.
//
// This file provides model functions that capture the relevant paths
// through applyAPILevelLimits using the supported pattern, and proves
// properties on those models.

//go:build reqproof_proof

package policy

import (
	"github.com/TykTechnologies/tyk/user"
)

// ---
// Lemma 1: QuotaMax never goes negative
// ---
//
// Real path in applyAPILevelLimits:
//
//   if currAD.Limit.QuotaMax != policyAD.Limit.QuotaMax &&
//      greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
//       policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
//   }
//
// Model: when the guard is true, the max-of-two semantics ensure the
// result is at least as large as both inputs, so non-negative stays
// non-negative. When the guard is false, QuotaMax is unchanged.
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:lemma apply_api_limits_quota_max_nonneg_model proves applyAPILevelQuotaMaxModel(policyAD, currAD).Limit.QuotaMax >= 0
func applyAPILevelQuotaMaxModel(policyAD, currAD user.AccessDefinition) user.AccessDefinition {
	if currAD.Limit.QuotaMax == policyAD.Limit.QuotaMax || !greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
		return policyAD
	}
	policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
	return policyAD
}

// ---
// Lemma 2: SetBy is propagated when QuotaMax is updated
// ---
//
// In the real body, when QuotaMax is updated (currAD's value is larger),
// the `updated` flag triggers copying SetBy from currAD. This model
// mirrors that behavior.
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires policyAD.Limit.QuotaMax < currAD.Limit.QuotaMax
// reqproof:lemma apply_api_limits_quota_max_setby_model proves applyAPILevelQuotaMaxSetByModel(policyAD, currAD).Limit.SetBy == currAD.Limit.SetBy
func applyAPILevelQuotaMaxSetByModel(policyAD, currAD user.AccessDefinition) user.AccessDefinition {
	if currAD.Limit.QuotaMax == policyAD.Limit.QuotaMax || !greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
		return policyAD
	}
	policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
	policyAD.Limit.SetBy = currAD.Limit.SetBy
	return policyAD
}

// ---
// Lemma 3: QuotaRenewalRate stays non-negative when the larger-wins path
// is taken
// ---
//
// In the real body, QuotaRenewalRate is overwritten by currAD's value
// when that value is larger (by greaterThanInt64).
//
// reqproof:requires policyAD.Limit.QuotaRenewalRate >= 0
// reqproof:requires currAD.Limit.QuotaRenewalRate >= 0
// reqproof:lemma apply_api_limits_quota_renewal_rate_model proves applyAPILevelQuotaRenewalRateModel(policyAD, currAD).Limit.QuotaRenewalRate >= 0
func applyAPILevelQuotaRenewalRateModel(policyAD, currAD user.AccessDefinition) user.AccessDefinition {
	if !greaterThanInt64(currAD.Limit.QuotaRenewalRate, policyAD.Limit.QuotaRenewalRate) {
		return policyAD
	}
	policyAD.Limit.QuotaRenewalRate = currAD.Limit.QuotaRenewalRate
	return policyAD
}

// ---
// Lemma 4: QuotaMax == -1 resets QuotaRenewalRate to 0
// ---
//
// In the real body, when policyAD.Limit.QuotaMax == -1 (unlimited),
// QuotaRenewalRate is unconditionally reset to 0. This models
// lines 685-687 of apply.go.
//
// reqproof:requires policyAD.Limit.QuotaMax == -1
// reqproof:lemma apply_api_limits_quota_max_neg_one_resets_renewal proves applyAPILevelQuotaMaxNegOneModel(policyAD).Limit.QuotaRenewalRate == 0
func applyAPILevelQuotaMaxNegOneModel(policyAD user.AccessDefinition) user.AccessDefinition {
	if policyAD.Limit.QuotaMax != -1 {
		return policyAD
	}
	policyAD.Limit.QuotaRenewalRate = 0
	return policyAD
}

// ---
// Lemma 5: QuotaMax is preserved when currAD's value is NOT larger
// (the identity path of Lemma 1's model)
// ---
//
// In the real body, when currAD's QuotaMax is <= policyAD's, the
// QuotaMax comparison guard fails and QuotaMax is not updated. This
// model verifies the identity case.
//
// reqproof:requires policyAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax >= 0
// reqproof:requires currAD.Limit.QuotaMax <= policyAD.Limit.QuotaMax
// reqproof:lemma apply_api_limits_quota_max_identity proves applyAPILevelQuotaMaxIdentityModel(policyAD, currAD).Limit.QuotaMax == policyAD.Limit.QuotaMax
func applyAPILevelQuotaMaxIdentityModel(policyAD, currAD user.AccessDefinition) user.AccessDefinition {
	if currAD.Limit.QuotaMax == policyAD.Limit.QuotaMax || !greaterThanInt64(currAD.Limit.QuotaMax, policyAD.Limit.QuotaMax) {
		return policyAD
	}
	policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
	return policyAD
}
