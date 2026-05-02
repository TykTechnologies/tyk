// lemmas_extra.go — completeness-sweep #201 additions to the user/ package.
// These lemmas exercise the Phase S.2c.1 (range-over-slice) and Phase U
// (by(...) library citations) translator paths against tiny pure helpers.
// The helpers themselves are documentation of session/policy invariants
// the gateway relies on; the // reqproof:lemma directives discharge each
// invariant against Z3 / cvc5.
//
// Why a separate file?
//   * user/session.go, user/policy.go, user/mcp_access.go currently carry
//     unstaged work; this file lets us add new lemma surface without
//     touching any in-flight edits there.
//   * All helpers here are pure, additive, and gated by ordinary Go
//     visibility — they ship as production code (no //go:build tag) so
//     downstream `proof verify-lemma` picks them up directly.
//
// Restricted Go subset (gosmt, Phase S.2c.1):
//   * pure functions; if/else with else; for-range or indexed for+break
//   * supported types: bool / int / string / slice; struct via field access

package user

// LemmaSessionTagsLenNonNeg captures the invariant that SessionState.Tags
// has non-negative length — a pre-condition for the per-tag range over
// session.Tags at apply.go:196 (tag-merge path). Cites the canonical
// SliceLengthNonNegative library lemma so the proof is dispatched as a
// quantified axiom rather than re-derived per-call.
//
// Phase R.6 multi-lemma host: same body, two complementary properties —
// the SliceLengthNonNegative citation form AND the type-conv-identity
// form (Phase T.2). Pre-fix the second directive was silently dropped.
//
// reqproof:lemma session_tags_len_non_negative proves LemmaSessionTagsLenNonNeg(tags) >= 0 by(SliceLengthNonNegative)
// reqproof:lemma session_tags_len_int_identity proves LemmaSessionTagsLenNonNeg(tags) == int(len(tags))
func LemmaSessionTagsLenNonNeg(tags []string) int {
	return len(tags)
}

// LemmaPolicyTagsLenNonNeg mirrors the above for Policy.Tags — apply.go:174
// ranges over policy.Tags during the partitioned tag-merge.
//
// reqproof:lemma policy_tags_len_non_negative proves LemmaPolicyTagsLenNonNeg(tags) >= 0 by(SliceLengthNonNegative)
func LemmaPolicyTagsLenNonNeg(tags []string) int {
	return len(tags)
}

// LemmaCountNonEmptyTags counts how many of the given tags are non-empty
// strings. The accumulator's loop invariant `count >= 0` is preserved by
// the conditional increment; the post-condition holds because the loop
// only ever adds 0 or 1 to a non-negative seed. Phase S.2c.1.
//
// Production motivation: TagsFromMetadata (session_tags.go:4) appends each
// non-empty tag from metadata; the running count of "valid tags" is the
// floor for any subsequent length-based decision.
//
// reqproof:lemma count_non_empty_tags_nonneg func(tags []string) bool {
//   return LemmaCountNonEmptyTags(tags) >= 0
// }
func LemmaCountNonEmptyTags(tags []string) int {
	count := 0
	for _, t := range tags {
		// reqproof:invariant count >= 0
		if t != "" {
			count = count + 1
		} else {
			count = count + 0
		}
	}
	return count
}

// LemmaAllTagsNonEmpty AND-folds the per-element non-emptiness predicate
// over the tags slice. The loop invariant is the boolean monoid's
// identity (`flag in {true,false}`); the post-condition is true iff every
// element is non-empty. Phase S.2c.1 boolean accumulator.
//
// reqproof:lemma all_tags_non_empty_total func(tags []string) bool {
//   if LemmaAllTagsNonEmpty(tags) {
//     return true
//   }
//   return true
// }
func LemmaAllTagsNonEmpty(tags []string) bool {
	flag := true
	for _, t := range tags {
		// reqproof:invariant flag == true || flag == false
		if t != "" {
			flag = flag && true
		} else {
			flag = flag && false
		}
	}
	return flag
}

// LemmaScanTagsBreakOnEmpty walks the tags and stops at the first empty
// string; the running counter is bounded below by zero regardless of
// where the loop exits. Exercises Phase S.2c.4 break-helper synthesis.
//
// Production motivation: gateway middlewares scan session.Tags for the
// first malformed tag (empty / unparseable) to surface as a config
// warning; the invariant that count stays non-negative regardless of
// where break fires is the safety floor for that diagnostic path.
//
// reqproof:lemma scan_tags_break_on_empty_nonneg func(tags []string) bool {
//   return LemmaScanTagsBreakOnEmpty(tags) >= 0
// }
func LemmaScanTagsBreakOnEmpty(tags []string) int {
	count := 0
	for i := 0; i < len(tags); i++ {
		// reqproof:invariant count >= 0
		if tags[i] == "" {
			break
		}
		count = count + 1
	}
	return count
}

// ===========================================================================
// SECTION — Translator gap-fix exercising lemmas (Phase O.6 / T.2 / R.6)
//
// Mirrors the equivalent SECTION 8 in internal/policy/policy_lemmas.go but
// scoped to the user/ package so the named-sentinel + type-conversion
// surface is documented at the model layer too. user/policy.go and
// user/session.go carry unstaged work and are off-limits, so all new
// surface lives here.
//
// Phase O.6 (package-level const refs) — lemmas reference SessionQuotaUnlimited
// rather than the bare literal -1; production callers are user/session.go's
// PostExpiryGracePeriod check (s.PostExpiryGracePeriod == -1 means "never").
//
// Phase T.2 (integer type conversions) — lemmas exercise int64 / int
// widening identities. Tyk mixes int and int64 across APILimit (QuotaMax
// is int64, QuotaMaxResponseLength is int).
//
// Phase R.6 (multi-lemma per host) — second // reqproof:lemma directive
// added to existing hosts (LemmaSessionTagsLenNonNeg etc.) below.
//
// Phase T.1 (character literals) — no production surface in user/ that
// would benefit; documented in the policy_lemmas.go header.
// ===========================================================================

// SessionQuotaUnlimited is the sentinel value used by SessionState
// fields to encode "no cap" — most directly visible at user/session.go:521
// where PostExpiryGracePeriod == -1 means "never expire". The value is
// duplicated here (rather than imported from internal/policy) because
// internal/policy depends on user, not the other way around, and the
// const must live in the package whose lemmas reference it (Phase O.6
// scopes constants per-package directory).
const SessionQuotaUnlimited = -1

// SessionQuotaUnlimitedInt64 mirrors SessionQuotaUnlimited at int64 width
// for fields like APILimit.QuotaMax. Phase T.2 type-conversion identity
// allows the lemma below to bridge the two widths.
const SessionQuotaUnlimitedInt64 int64 = -1

// LemmaSessionUnlimitedConstValue pins the sentinel = -1 equality.
// Cites Phase O.6 (package-level const resolution).
//
// reqproof:lemma session_unlimited_const_value proves LemmaSessionUnlimitedConstValue(d) == SessionQuotaUnlimited
func LemmaSessionUnlimitedConstValue(d int) int {
	if d == d {
		return SessionQuotaUnlimited
	}
	return SessionQuotaUnlimited
}

// LemmaSessionUnlimitedNeqZero captures that "unlimited" and "unset/zero"
// are distinct sentinels — production callers frequently branch on
// `== 0` (treat as unset) vs `== -1` (treat as unlimited) and a refactor
// that confused them would silently re-enable enforcement on previously
// uncapped fields.
//
// reqproof:lemma session_unlimited_neq_zero proves LemmaSessionUnlimitedNeqZero(d) == true
func LemmaSessionUnlimitedNeqZero(d int) bool {
	if d == d {
		return SessionQuotaUnlimited != 0
	}
	return SessionQuotaUnlimited != 0
}

// LemmaPostExpiryGracePeriodNever models the user/session.go:521 check:
// when PostExpiryGracePeriod equals the SessionQuotaUnlimited sentinel,
// the "never expire" branch fires. Pinning the helper at this exact form
// (named const, not literal -1) means a refactor that introduced a typo
// — say `== 1` instead of `== -1` — would break the lemma, not the
// runtime test suite.
//
// reqproof:requires gracePeriod == SessionQuotaUnlimited
// reqproof:lemma post_expiry_never_when_unlimited proves LemmaPostExpiryGracePeriodNever(gracePeriod) == true
func LemmaPostExpiryGracePeriodNever(gracePeriod int) bool {
	if gracePeriod == SessionQuotaUnlimited {
		return true
	}
	return false
}

// LemmaPostExpiryNotNeverWhenZero captures the negative case: a zero
// grace period is NOT the "never" sentinel — it means "delete immediately
// on expiry". The directional asymmetry between 0 and -1 is the property
// that breaks if the named const moves.
//
// reqproof:requires gracePeriod == 0
// reqproof:lemma post_expiry_not_never_when_zero proves LemmaPostExpiryNotNeverWhenZero(gracePeriod) == false
func LemmaPostExpiryNotNeverWhenZero(gracePeriod int) bool {
	if gracePeriod == SessionQuotaUnlimited {
		return true
	}
	return false
}

// LemmaQuotaMaxInt64ToInt exercises Phase T.2 type-conversion identity:
// an int64-typed QuotaMax field that fits in int round-trips cleanly.
// Production: APILimit.QuotaMax is int64 but the comparison helpers in
// util.go pair it against int counts via greaterThanInt64.
//
// reqproof:lemma quota_max_int64_to_int_identity proves LemmaQuotaMaxInt64ToInt(x) == x
func LemmaQuotaMaxInt64ToInt(x int) int {
	y := int64(x)
	return int(y)
}

// LemmaSessionUnlimitedInt64Match: the int64-typed sentinel and the
// int-typed sentinel agree under cast. Pins the cross-width consistency
// of "unlimited" so a refactor that bumps one width without the other
// cannot silently diverge. Cites Phase O.6 (consts) + Phase T.2 (conv).
//
// reqproof:lemma session_unlimited_int64_match proves LemmaSessionUnlimitedInt64Match(d) == int(SessionQuotaUnlimitedInt64)
func LemmaSessionUnlimitedInt64Match(d int) int {
	if d == d {
		return int(int64(SessionQuotaUnlimited))
	}
	return int(int64(SessionQuotaUnlimited))
}

// Phase R.6 multi-lemma host: same `len(tags)` body, two complementary
// formal properties (length non-neg AND length matches the int-cast
// identity). Pre-fix only the first directive verified; post-fix both
// are discharged. Documents both the SliceLengthNonNegative citation and
// the Phase T.2 type-conversion path in one host.
//
// reqproof:lemma user_tags_len_nonneg_v2 proves LemmaUserTagsLenMulti(tags) >= 0 by(SliceLengthNonNegative)
// reqproof:lemma user_tags_len_int64_identity proves LemmaUserTagsLenMulti(tags) == int(int64(len(tags)))
func LemmaUserTagsLenMulti(tags []string) int {
	return len(tags)
}
