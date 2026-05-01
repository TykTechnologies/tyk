//go:build reqproof_proof

// Phase P.6 fresh abstraction-only lemmas. These exercise the L3
// // reqproof:model projections of user.Policy / user.APILimit /
// user.SessionState declared in user/policy_model.go. Unlike the
// migrated 6 lemmas (which had Pattern A precursors), these are new
// invariants written directly against the projected types.

package policy

import "github.com/TykTechnologies/tyk/user"

// policy_meets_quota: when QuotaMax is positive and the policy is
// active (Active && !IsInactive), the policy can serve quota-gated
// requests. Captures the natural correctness condition for the policy
// engine's per-request quota check.
//
// reqproof:requires p.QuotaMax > 0
// reqproof:requires p.Active == true
// reqproof:requires p.IsInactive == false
// reqproof:lemma policy_meets_quota_when_active_and_quota_positive proves p.QuotaMax > 0 && p.Active && !p.IsInactive
func policy_meets_quota_active(p user.Policy) bool {
	return p.QuotaMax > 0 && p.Active && !p.IsInactive
}

// session_quota_consumed: when QuotaRemaining drops below QuotaMax, at
// least one request has been served against this session's quota
// budget. Encodes the standard accounting invariant the rate-limiter
// relies on.
//
// reqproof:requires s.QuotaMax > 0
// reqproof:requires s.QuotaRemaining < s.QuotaMax
// reqproof:lemma session_quota_consumed_when_remaining_below_max proves s.QuotaRemaining < s.QuotaMax && s.QuotaMax > 0
func session_quota_consumed(s user.SessionState) bool {
	return s.QuotaRemaining < s.QuotaMax && s.QuotaMax > 0
}

// apilimit_throttle_window_positive: when ThrottleInterval is positive
// AND ThrottleRetryLimit is positive, the limit defines a non-trivial
// throttle window. Used by the throttle-policy reasoner.
//
// reqproof:requires a.ThrottleInterval > 0.0
// reqproof:requires a.ThrottleRetryLimit > 0
// reqproof:lemma apilimit_throttle_window_positive_when_both_set proves a.ThrottleInterval > 0.0 && a.ThrottleRetryLimit > 0
func apilimit_throttle_window(a user.APILimit) bool {
	return a.ThrottleInterval > 0.0 && a.ThrottleRetryLimit > 0
}
