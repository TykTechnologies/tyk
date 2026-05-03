//go:build reqproof_proof
// +build reqproof_proof

// Phase FF/NN.1 — Tyk migration: cross-package // reqproof:model
// abstractions for user.* types the engine methods take. Each directive
// is import-attached on its own import spec.
//
// The AccessDefinition model lives here (rather than in user/) because
// the engine-method lemmas in this package need richer field exposure
// than user/ would carry on its public API surface.
//
// Phase NN.1 limitation: cross-package model directives for user.Policy
// and user.PolicyPartitions WERE drafted here, but the audit-step
// re-derivation of `models[abs.SMTName] = abs` collapses both the user-
// side host-attached model and this file's directive under the bare
// SMTName "Policy" / "PolicyPartitions" with map-iteration order
// determining the winner. Without editing user/ to expand the
// host-attached models (which the workflow forbids), the additional
// fields cannot be made to win priority. Documented as Wall:
// cross-package model override priority.
package policy

// reqproof:model user.AccessDefinition
//   field APIID string
//   field Limit user.APILimit
//   field AllowanceScope string
//   field DisableIntrospection bool
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
	_ model.PolicyProvider
	_ logrus.Logger
)
