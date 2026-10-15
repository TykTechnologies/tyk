package keys

import (
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/user"
)

// DBAccessDefinition is the access-rights shape the Dashboard stores and
// serves from /system/policies. It differs from user.AccessDefinition in
// that Limit is a pointer.
type DBAccessDefinition struct {
	APIName              string                       `json:"api_name"`
	APIID                string                       `json:"api_id"`
	Versions             []string                     `json:"versions"`
	AllowedURLs          []user.AccessSpec            `bson:"allowed_urls" json:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type               `json:"restricted_types"`
	AllowedTypes         []graphql.Type               `json:"allowed_types"`
	DisableIntrospection bool                         `json:"disable_introspection"`
	FieldAccessRights    []user.FieldAccessDefinition `json:"field_access_rights"`
	Limit                *user.APILimit               `json:"limit"`

	// Endpoints contains endpoint rate limit settings.
	Endpoints user.Endpoints `json:"endpoints,omitempty"`

	JSONRPCMethods             []user.JSONRPCMethodLimit `json:"json_rpc_methods,omitempty"`
	JSONRPCMethodsAccessRights user.AccessControlRules   `json:"json_rpc_methods_access_rights,omitzero"`
	MCPPrimitives              []user.MCPPrimitiveLimit  `json:"mcp_primitives,omitempty"`
	MCPAccessRights            user.MCPAccessRights      `json:"mcp_access_rights,omitzero"`
}

// ToRegularAD converts the Dashboard access definition into the gateway's
// user.AccessDefinition.
func (d *DBAccessDefinition) ToRegularAD() user.AccessDefinition {
	ad := user.AccessDefinition{
		APIName:              d.APIName,
		APIID:                d.APIID,
		Versions:             d.Versions,
		AllowedURLs:          d.AllowedURLs,
		RestrictedTypes:      d.RestrictedTypes,
		AllowedTypes:         d.AllowedTypes,
		DisableIntrospection: d.DisableIntrospection,
		FieldAccessRights:    d.FieldAccessRights,
		Endpoints:            d.Endpoints,
	}

	if d.Limit != nil {
		ad.Limit = *d.Limit
	}

	ad.JSONRPCMethods = d.JSONRPCMethods
	ad.JSONRPCMethodsAccessRights = d.JSONRPCMethodsAccessRights
	ad.MCPPrimitives = d.MCPPrimitives
	ad.MCPAccessRights = d.MCPAccessRights

	return ad
}

// DBPolicy is a policy as served by the Dashboard (/system/policies).
type DBPolicy struct {
	user.Policy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

// ToRegularPolicy converts a Dashboard policy into the gateway's user.Policy.
func (d *DBPolicy) ToRegularPolicy() user.Policy {
	policy := d.Policy
	policy.AccessRights = make(map[string]user.AccessDefinition)

	for k, v := range d.AccessRights {
		policy.AccessRights[k] = v.ToRegularAD()
	}
	return policy
}
