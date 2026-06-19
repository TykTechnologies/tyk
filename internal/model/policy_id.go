package model

type (
	// BasePolicyId
	// Base struct to reduce.
	// Created to reduce number of marker method implementations.
	BasePolicyId struct{}

	// ScopedCustomPolicyId represents any policy identifier (database and custom)
	ScopedCustomPolicyId struct {
		BasePolicyId // nolint:unused
		orgId        string
		id           string
	}

	// NonScopedLastInsertedPolicyId
	// Retrieves lastly inserted policy by custom id.
	// This strategy is created to support backward compatibility.
	NonScopedLastInsertedPolicyId string
)

// markerPolicyId marker
//
// SYS-REQ-077
//
//nolint:unused
func (i BasePolicyId) markerPolicyId() {}

var (
	_ PolicyID = ScopedCustomPolicyId{}
	_ PolicyID = NonScopedLastInsertedPolicyId("")
)

// NewScopedCustomPolicyId creates custom policy identifier
// SYS-REQ-077
func NewScopedCustomPolicyId(orgId, customId string) ScopedCustomPolicyId {
	return ScopedCustomPolicyId{
		orgId: orgId,
		id:    customId,
	}
}

// SYS-REQ-077
func (c ScopedCustomPolicyId) OrgId() string {
	return c.orgId
}

// SYS-REQ-077
func (c ScopedCustomPolicyId) Id() string {
	return c.id
}

// SYS-REQ-077
func (c ScopedCustomPolicyId) String() string {
	return c.id
}

// SYS-REQ-077
func (c ScopedCustomPolicyId) markerPolicyId() {}

// SYS-REQ-077
func (c NonScopedLastInsertedPolicyId) String() string {
	return string(c)
}

// SYS-REQ-077
func (c NonScopedLastInsertedPolicyId) markerPolicyId() {}
