//go:build reqproof_proof

// policy_model.go declares Phase P.3 // reqproof:model projections for
// the user package's production types. The block lists ONLY the fields
// reqproof lemmas read; all other production fields are intentionally
// projected away so the SMT solver sees a minimal, correct view.
//
// Build-tagged reqproof_proof so the file is invisible to the standard
// Go toolchain. Reviewers and the auditor can still see it; the verifier
// reads it via the same scanner the lemma orchestrator uses.

package user

// reqproof:model
// field QuotaMax int64
// field QuotaRenewalRate int64
// field Rate float64
// field Per float64
// field ThrottleInterval float64
// field ThrottleRetryLimit int
// field Active bool
// field IsInactive bool
type _ Policy

// reqproof:model
// field Rate float64
// field Per float64
// field ThrottleInterval float64
// field ThrottleRetryLimit int
// field MaxQueryDepth int
// field QuotaMax int64
// field QuotaRenews int64
// field QuotaRemaining int64
// field QuotaRenewalRate int64
// field SetBy string
type _ APILimit

// reqproof:model
// field Rate float64
// field Per float64
// field QuotaMax int64
// field QuotaRenews int64
// field QuotaRemaining int64
// field QuotaRenewalRate int64
// field ThrottleRetryLimit int
// field Expires int64
// field IsInactive bool
type _ SessionState
