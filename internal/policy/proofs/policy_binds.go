//go:build reqproof_proof
// +build reqproof_proof

// Package proofs hosts Phase DD `binds-to` lemmas that attach to the
// internal/policy production code without modifying it. Each lemma's
// funclit body is a TRUSTED hypothesis about what the bound function
// does; manual review keeps the two coupled.
//
// At verification time the orchestrator translates the funclit body as a
// summary of the bound function and dispatches it to the SMT solver. On
// PROVED, the (target, lemma) hash pair is recorded in
// .proof/lemma-bindings.json. The audit-time `lemma_binding_freshness`
// check (Phase DD.3) compares persisted hashes to live code, surfacing
// drift in either direction.
//
// IMPORTANT — Phase DD orchestrator deferral: these binds-to lemmas
// document hypotheses and feed the binding-freshness audit, but the
// `verify-lemma` orchestrator wiring that DISPATCHES them to a solver
// is not yet implemented. They round-trip through the scanner / audit
// path today; their solver dispatch is a tracked follow-up.
//
// The HEADLINE Phase EE summary work targets the int64 helpers in
// internal/policy/util.go (greaterThanInt64) — see the directly-attached
// lemmas there. The binds-to lemmas below cover Service.Apply,
// Service.applyAPILevelLimits, and Service.ClearSession to demonstrate
// the file-binding pattern across the engine surface that translator
// limits prevent us from summarising in-line (qualified user.*/model.*
// types currently reject in the gosmt restricted Go subset).
package proofs

// reqproof:lemma apply_returns_error_or_nil
//   binds-to policy.(*Service).Apply
//   func(t *policy.Service, session *user.SessionState) error {
//     // Hypothesis: Apply on a session with no policies and a non-nil
//     // storage returns nil. The real body has many other branches; this
//     // lemma pins the no-policies invariant the gateway middleware
//     // relies on (skip-key-on-empty-policy path).
//     return nil
//   }
// reqproof:lemma apply_api_level_limits_quota_max_monotone_binding
//   binds-to policy.(*Service).applyAPILevelLimits
//   func(t *policy.Service, policyAD user.AccessDefinition, currAD user.AccessDefinition) user.AccessDefinition {
//     // Hypothesis: applyAPILevelLimits returns an AccessDefinition
//     // whose Limit.QuotaMax is the larger of the two inputs. Mirrors
//     // the abstract LemmaPolicy quota_max invariants, now bound to the
//     // real engine method via the Phase DD file-binding pattern.
//     if currAD.Limit.QuotaMax > policyAD.Limit.QuotaMax {
//       policyAD.Limit.QuotaMax = currAD.Limit.QuotaMax
//     }
//     return policyAD
//   }
// reqproof:lemma clear_session_zeros_quota_when_partitioned
//   binds-to policy.(*Service).ClearSession
//   func(t *policy.Service, session *user.SessionState) error {
//     // Hypothesis: ClearSession with a quota-partitioned policy zeroes
//     // session.QuotaMax / session.QuotaRemaining so the subsequent
//     // applyPartitions can install the policy's quota without losing
//     // the race against the prior session value.
//     session.QuotaMax = 0
//     session.QuotaRemaining = 0
//     return nil
//   }
import (
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/user"
)

// Compile-time references so `go vet` does not flag the imports as
// unused. The lemma claims live in the doc comments above the import.
var (
	_ = policy.Service{}
	_ user.SessionState
	_ user.AccessDefinition
)
