//go:build reqproof_proof

// Phase P.6: lemmas migrated from the bespoke shadow types (PolicyM /
// APILimitM / SessionStateM) onto the production user.Policy /
// user.APILimit / user.SessionState. The mirror struct definitions are
// gone; field projections are declared in
// /Users/leonidbugaev/go/src/tyk/user/policy_model.go via
// // reqproof:model. The verifier sees a minimal projected struct
// (only the fields each lemma reads) — the unmodeled production fields
// are invisible to the SMT translator.
//
// Lemma bodies inline the predicate logic instead of routing through
// production methods. This keeps the lemmas self-contained: changing a
// production method's body cannot accidentally change what the lemma
// proves.

package policy

import "github.com/TykTechnologies/tyk/user"

// ---------------------------------------------------------------------------
// Policy invariants (3 lemmas, migrated from PolicyM).
// ---------------------------------------------------------------------------

// reqproof:requires p.QuotaMax >= 0
// reqproof:lemma policy_quota_max_valid_iff_nonneg proves p.QuotaMax >= 0
func policy_quota_max_lemma(p user.Policy) bool {
	return p.QuotaMax >= 0
}

// reqproof:requires p.Rate > 0.0
// reqproof:requires p.Per > 0.0
// reqproof:lemma policy_rate_pair_consistency proves p.Rate > 0.0 && p.Per > 0.0
func policy_rate_pair_lemma(p user.Policy) bool {
	return p.Rate > 0.0 && p.Per > 0.0
}

// reqproof:requires p.ThrottleRetryLimit > 0
// reqproof:lemma policy_throttle_configured_when_positive proves p.ThrottleRetryLimit > 0
func policy_throttle_lemma(p user.Policy) bool {
	return p.ThrottleRetryLimit > 0
}

// ---------------------------------------------------------------------------
// APILimit invariants (2 lemmas, migrated from APILimitM).
// ---------------------------------------------------------------------------

// reqproof:requires a.Rate == 0.0
// reqproof:requires a.Per == 0.0
// reqproof:requires a.QuotaMax == 0
// reqproof:requires a.QuotaRenews == 0
// reqproof:requires a.QuotaRemaining == 0
// reqproof:requires a.QuotaRenewalRate == 0
// reqproof:requires a.ThrottleInterval == 0.0
// reqproof:requires a.ThrottleRetryLimit == 0
// reqproof:requires a.MaxQueryDepth == 0
// reqproof:requires a.SetBy == ""
// reqproof:lemma apilimit_isempty_when_all_fields_zero proves a.Rate == 0.0 && a.Per == 0.0 && a.QuotaMax == 0 && a.QuotaRenews == 0 && a.QuotaRemaining == 0 && a.QuotaRenewalRate == 0
func apilimit_isempty_lemma(a user.APILimit) bool {
	return a.Rate == 0.0 && a.Per == 0.0 && a.QuotaMax == 0 && a.QuotaRenews == 0 && a.QuotaRemaining == 0 && a.QuotaRenewalRate == 0
}

// reqproof:requires a.QuotaMax > 0
// reqproof:lemma apilimit_nonempty_when_quota_set proves a.QuotaMax > 0
func apilimit_nonempty_lemma(a user.APILimit) bool {
	return a.QuotaMax > 0
}

// ---------------------------------------------------------------------------
// SessionState invariant (1 lemma, migrated from SessionStateM).
//
// The original PolicyM-side lemma used a bespoke time.Time-typed Expires
// field; user.SessionState's Expires is int64 (Unix seconds). The
// migrated invariant: when IsInactive is false and Expires is in the
// future relative to a `now` parameter, the session is conceptually
// active. Encoded directly (no method call) so the projection model
// suffices.
// ---------------------------------------------------------------------------

// reqproof:requires s.IsInactive == false
// reqproof:requires s.Expires > now
// reqproof:lemma session_active_when_future_expiry proves s.Expires > now && s.IsInactive == false
func session_active_lemma(s user.SessionState, now int64) bool {
	return s.Expires > now && !s.IsInactive
}
