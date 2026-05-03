//go:build reqproof_proof
// +build reqproof_proof

// Phase FF/NN.1/OO.1 — Tyk migration: cross-package // reqproof:model
// abstractions for user.* types the engine methods take. All three
// user.* directives attach to the single (blank) import below — multiple
// reqproof directives in one comment group are scanned independently
// and each registers its own L3 entry.
//
// Phase OO.1: cross-package model directives for user.Policy and
// user.PolicyPartitions are now wired alongside the AccessDefinition
// model. The audit-step priority bug (re-derived
// `models[absDir+SMTName]` keying the import-attached directive under
// `policy.X` while leaving `user.X` pointing at the smaller
// host-attached model) is fixed in
// pkg/lemma/prover/orchestration.go: the audit map now consumes the
// AbstractionRegistry's id-keyed Entries() so cross-package priority
// resolution matches the register-pass winner. With that fix, the
// import-attached directives below extend the user-side host model
// fields without editing user/ source — the registry's last-write-wins
// rule (under the Phase NN.1 prepend) promotes the import-attached
// version to win the qualified `user.X` slot.
//
// Field selection rationale: only the engine-method-touched fields are
// modeled. Adding more fields would slow translation without unlocking
// any pending lemma; adding fewer would cause E_FIELD_ESCAPE on the
// applyPartitions / applyPerAPI lemma bodies.
package policy

// reqproof:model user.AccessDefinition
//   field APIID string
//   field Limit user.APILimit
//   field AllowanceScope string
//   field DisableIntrospection bool
//
// reqproof:model user.Policy
//   field AccessRights map[string]user.AccessDefinition
//   field Partitions user.PolicyPartitions
//   field ID string
//   field Active bool
//   field IsInactive bool
//   field QuotaMax int64
//   field QuotaRenewalRate int64
//   field Rate float64
//   field Per float64
//   field ThrottleInterval float64
//   field ThrottleRetryLimit int
//
// reqproof:model user.PolicyPartitions
//   field Quota bool
//   field RateLimit bool
//   field Complexity bool
//   field Acl bool
//   field PerAPI bool
import _ "github.com/TykTechnologies/tyk/user"

// reqproof:abstract model.PolicyProvider sort=Opaque
import "github.com/TykTechnologies/tyk/internal/model"

// reqproof:abstract logrus.Logger sort=Opaque
import "github.com/sirupsen/logrus"

import "github.com/TykTechnologies/tyk/user"

// Compile-time references so `go vet` does not flag the imports as unused.
// The reqproof:* directives above are the load-bearing payload.
var (
	_ user.AccessDefinition
	_ user.APILimit
	_ user.Policy
	_ user.PolicyPartitions
	_ model.PolicyProvider
	_ logrus.Logger
)
