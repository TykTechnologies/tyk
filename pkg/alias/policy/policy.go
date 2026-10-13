// Package policy re-exports the policy application service from
// internal/policy so that it can be consumed outside the tyk module
// (for example by the Dashboard running the control-plane library).
package policy

import "github.com/TykTechnologies/tyk/internal/policy"

type (
	// Service applies policies to a session. See internal/policy.Service.
	Service = policy.Service
	// Store is an in-memory PolicyProvider over a slice of policies.
	Store = policy.Store
)

var (
	// New returns a Service for the given org scope and policy provider.
	New = policy.New
	// NewStore builds a Store from a slice of policies.
	NewStore = policy.NewStore
	// MergeAllowedURLs merges two allowed-URL lists.
	MergeAllowedURLs = policy.MergeAllowedURLs
)
