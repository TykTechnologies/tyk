//go:build reqproof_proof
// +build reqproof_proof

// Phase FF — Tyk migration: cross-package // reqproof:model abstractions
// for user.* types the engine methods take. Lives in internal/policy as a
// sibling of apply.go so the Phase P scanner picks the directives up when
// verifying lemmas defined in this package.
//
// Note: APILimit, SessionState, and Policy already carry models in the
// user package next to their definitions (host-attached form). The
// import-attached directive below models the missing AccessDefinition
// type for engine methods that need it. Fields use the int-typed
// surface relevant to the Apply / applyAPILevelLimits properties; the
// real production type carries reference / map / pointer fields whose
// semantics the lemmas do NOT depend on.
package policy

// reqproof:model user.AccessDefinition
//   field Limit user.APILimit
//   field AllowanceScope string
import "github.com/TykTechnologies/tyk/user"

// reqproof:abstract model.PolicyProvider sort=Opaque
import "github.com/TykTechnologies/tyk/internal/model"

// reqproof:abstract logrus.Logger sort=Opaque
import "github.com/sirupsen/logrus"

// Compile-time reference so `go vet` does not flag the import as unused.
// The directive above is the load-bearing payload.
var (
	_ user.AccessDefinition
	_ user.APILimit
	_ model.PolicyProvider
	_ logrus.Logger
)
