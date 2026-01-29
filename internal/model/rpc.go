package model

import "github.com/TykTechnologies/tyk/apidef"

// This contains the shim for rpc data model types.
// They are used from tests, and just pipe through
// the apidef types to avoid import cycles.
type (
	GroupLoginRequest    = apidef.GroupLoginRequest
	GroupKeySpaceRequest = apidef.GroupKeySpaceRequest
	DefRequest           = apidef.DefRequest
	InboundData          = apidef.InboundData
	KeysValuesPair       = apidef.KeysValuesPair
)

// These are health check shims.
type (
	HealthCheckItem     = apidef.HealthCheckItem
	HealthCheckResponse = apidef.HealthCheckResponse
	HealthCheckStatus   = apidef.HealthCheckStatus

	HostDetails = apidef.HostDetails
	NodeData    = apidef.NodeData
	GWStats     = apidef.GWStats

	// Loaded resource info types
	LoadedAPIInfo    = apidef.LoadedAPIInfo
	LoadedPolicyInfo = apidef.LoadedPolicyInfo
)

// Other.
const (
	Pass      = apidef.Pass
	Warn      = apidef.Warn
	Fail      = apidef.Fail
	System    = apidef.System
	Datastore = apidef.Datastore
)
