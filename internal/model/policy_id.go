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

	// NonScopedPolicyId
	// Has to be used to retried policy by id non scoped.
	// Does not return eny policy and error if ambiguous state occurs.
	// Represents more propert behaviour than NonScopedLastInsertedPolicyId.
	NonScopedPolicyId string

	// NonScopedLastInsertedPolicyId
	// Retrieves lastly inserted policy by custom id.
	// This strategy is created to support backward compatibility.
	NonScopedLastInsertedPolicyId string
)

// markerPolicyId marker
//
//nolint:unused
func (i BasePolicyId) markerPolicyId() {}

var (
	_ PolicyID = NonScopedPolicyId("")
	_ PolicyID = ScopedCustomPolicyId{}
	_ PolicyID = NonScopedLastInsertedPolicyId("")
)

// NewScopedCustomPolicyId creates custom policy identifier
func NewScopedCustomPolicyId(orgId, customId string) ScopedCustomPolicyId {
	return ScopedCustomPolicyId{
		orgId: orgId,
		id:    customId,
	}
}

func (c ScopedCustomPolicyId) OrgId() string {
	return c.orgId
}

func (c ScopedCustomPolicyId) Id() string {
	return c.id
}

func (c ScopedCustomPolicyId) String() string {
	return c.id
}

func (c ScopedCustomPolicyId) customKey() customKey {
	return customKey(c.id)
}

func (c ScopedCustomPolicyId) markerPolicyId() {}

func (c NonScopedPolicyId) String() string {
	return string(c)
}
func (c NonScopedPolicyId) markerPolicyId() {}

func (c NonScopedLastInsertedPolicyId) String() string {
	return string(c)
}
func (c NonScopedLastInsertedPolicyId) markerPolicyId() {}
