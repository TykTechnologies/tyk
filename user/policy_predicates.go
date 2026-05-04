// Predicate helpers for session/policy invariants.
// Each helper carries a // reqproof:lemma directive.

package user

// LemmaSessionTagsLenNonNeg captures the invariant that SessionState.Tags
// has non-negative length — a pre-condition for the per-tag range over
// session.Tags at apply.go:196 (tag-merge path). Cites the canonical
// SliceLengthNonNegative library lemma so the proof is dispatched as a
// quantified axiom rather than re-derived per-call.
//
// reqproof:lemma session_tags_len_non_negative proves LemmaSessionTagsLenNonNeg(tags) >= 0 by(SliceLengthNonNegative)
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
// the conditional increment.
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

// LemmaScanTagsBreakOnEmpty walks the tags and stops at the first empty
// string; the running counter is bounded below by zero regardless of
// where the loop exits.
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

// LemmaUserTagsLenMulti captures that any tag slice's length is non-negative.
// Delegates the proof to the standard library lemma SliceLengthNonNegative.
//
// reqproof:lemma user_tags_len_nonneg_v2 proves LemmaUserTagsLenMulti(tags) >= 0 by(SliceLengthNonNegative)
func LemmaUserTagsLenMulti(tags []string) int {
	return len(tags)
}
