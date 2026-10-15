// Package model re-exports the policy model types from internal/model so
// that they can be consumed outside the tyk module.
package model

import "github.com/TykTechnologies/tyk/internal/model"

type (
	// PolicyProvider is the read interface over a policy set.
	PolicyProvider = model.PolicyProvider
	// PolicyID identifies a policy inside a PolicyProvider.
	PolicyID = model.PolicyID
	// Policies is the gateway's concrete PolicyProvider.
	Policies = model.Policies
	// PolicySetOpt configures NewPolicies.
	PolicySetOpt = model.PolicySetOpt
	// BrokenPolicyCb is invoked for policies that fail to load.
	BrokenPolicyCb = model.BrokenPolicyCb
	// InternalCollisionCb is invoked on internal ID collisions.
	InternalCollisionCb = model.InternalCollisionCb
	// ScopedCustomPolicyId is an org-scoped policy identifier.
	ScopedCustomPolicyId = model.ScopedCustomPolicyId
	// NonScopedLastInsertedPolicyId resolves a custom ID without org scope.
	NonScopedLastInsertedPolicyId = model.NonScopedLastInsertedPolicyId
)

var (
	// NewPolicies constructs an empty Policies set.
	NewPolicies = model.NewPolicies
	// WithCombined composes PolicySetOpt values.
	WithCombined = model.WithCombined
	// WithLoadFail sets the broken-policy callback.
	WithLoadFail = model.WithLoadFail
	// WithInternalCollision sets the collision callback.
	WithInternalCollision = model.WithInternalCollision
	// NewScopedCustomPolicyId builds an org-scoped policy identifier.
	NewScopedCustomPolicyId = model.NewScopedCustomPolicyId
	// EnsurePolicyId normalises a policy's ID fields.
	EnsurePolicyId = model.EnsurePolicyId
	// ErrPolicyNotFound is returned when a policy ID does not resolve.
	ErrPolicyNotFound = model.ErrPolicyNotFound
)
