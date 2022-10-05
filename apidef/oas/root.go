package oas

import (
	"sort"

	"github.com/TykTechnologies/tyk/apidef"
)

// XTykAPIGateway contains custom Tyk API extensions for the OAS definition.
type XTykAPIGateway struct {
	// Info contains the main metadata about the API definition.
	Info Info `bson:"info" json:"info"` // required
	// Upstream contains the configurations related to the upstream.
	Upstream Upstream `bson:"upstream" json:"upstream"` // required
	// Server contains the configurations related to the server.
	Server Server `bson:"server" json:"server"` // required
	// Middleware contains the configurations related to the proxy middleware.
	Middleware *Middleware `bson:"middleware,omitempty" json:"middleware,omitempty"`
}

// Fill fills *XTykAPIGateway from apidef.APIDefinition.
func (x *XTykAPIGateway) Fill(api apidef.APIDefinition) {
	x.Info.Fill(api)
	x.Upstream.Fill(api)
	x.Server.Fill(api)

	if x.Middleware == nil {
		x.Middleware = &Middleware{}
	}

	x.Middleware.Fill(api)
	if ShouldOmit(x.Middleware) {
		x.Middleware = nil
	}
}

// ExtractTo extracts *XTykAPIGateway into *apidef.APIDefinition.
func (x *XTykAPIGateway) ExtractTo(api *apidef.APIDefinition) {
	x.Info.ExtractTo(api)
	x.Upstream.ExtractTo(api)
	x.Server.ExtractTo(api)

	if x.Middleware != nil {
		x.Middleware.ExtractTo(api)
	}
}

// Info contains the main metadata about the API definition.
type Info struct {
	// ID is the unique ID of the API.
	// Tyk native API definition: `api_id`
	ID string `bson:"id" json:"id,omitempty"`
	// DBID is the unique database ID of the API.
	// Tyk native API definition: `id`
	DBID apidef.ObjectId `bson:"dbId" json:"dbId,omitempty"`
	// OrgID is the ID of the organisation which the API belongs to.
	// Tyk native API definition: `org_id`
	OrgID string `bson:"orgId" json:"orgId,omitempty"`
	// Name is the name of the API.
	// Tyk native API definition: `name`
	Name string `bson:"name" json:"name"` // required
	// Expiration date.
	Expiration string `bson:"expiration,omitempty" json:"expiration,omitempty"`
	// State holds configuration about API definition states (active, internal).
	State State `bson:"state" json:"state"` // required
	// Versioning holds configuration for API versioning.
	Versioning *Versioning `bson:"versioning,omitempty" json:"versioning,omitempty"`
}

// Fill fills *Info from apidef.APIDefinition.
func (i *Info) Fill(api apidef.APIDefinition) {
	i.ID = api.APIID
	i.DBID = api.Id
	i.OrgID = api.OrgID
	i.Name = api.Name
	i.Expiration = api.Expiration
	i.State.Fill(api)

	if i.Versioning == nil {
		i.Versioning = &Versioning{}
	}

	i.Versioning.Fill(api)
	if ShouldOmit(i.Versioning) {
		i.Versioning = nil
	}
}

// ExtractTo extracts *Info into an *apidef.APIDefinition.
func (i *Info) ExtractTo(api *apidef.APIDefinition) {
	api.APIID = i.ID
	api.Id = i.DBID
	api.OrgID = i.OrgID
	api.Name = i.Name
	api.Expiration = i.Expiration
	i.State.ExtractTo(api)

	if i.Versioning != nil {
		i.Versioning.ExtractTo(api)
	}

	// everytime
	api.VersionData.NotVersioned = true
	api.VersionData.DefaultVersion = ""
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		"": {},
	}
}

// State holds configuration about API definition states (active, internal).
type State struct {
	// Active enables the API.
	// Tyk native API definition: `active`
	Active bool `bson:"active" json:"active"` // required
	// Internal makes the API accessible only internally.
	// Tyk native API definition: `internal`
	Internal bool `bson:"internal,omitempty" json:"internal,omitempty"`
}

// Fill fills *State from apidef.APIDefinition.
func (s *State) Fill(api apidef.APIDefinition) {
	s.Active = api.Active
	s.Internal = api.Internal
}

// ExtractTo extracts *State to *apidef.APIDefinition.
func (s *State) ExtractTo(api *apidef.APIDefinition) {
	api.Active = s.Active
	api.Internal = s.Internal
}

// Versioning holds configuration for API versioning.
//
// Tyk native API definition: `version_data`.
type Versioning struct {
	// Enabled is a boolean flag, if set to `true` it will enable versioning of an API.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// Name contains the name of the version as entered by the user ("v1" or similar).
	Name string `bson:"name,omitempty" json:"name,omitempty"`
	// Default contains the default version name if a request is issued without a version.
	Default string `bson:"default" json:"default"` // required
	// Location contains versioning location information. It can be one of the following:
	//
	// - `header`,
	// - `url-param`,
	// - `url`.
	Location string `bson:"location" json:"location"` // required
	// Key contains the name of the key to check for versioning information.
	Key string `bson:"key" json:"key"` // required
	// Versions contains a list of versions that map to individual API IDs.
	Versions []VersionToID `bson:"versions" json:"versions"` // required
	// StripVersioningData is a boolean flag, if set to `true`, the API responses will be stripped of versioning data.
	StripVersioningData bool `bson:"stripVersioningData,omitempty" json:"stripVersioningData,omitempty"`
}

// Fill fills *Versioning from apidef.APIDefinition.
func (v *Versioning) Fill(api apidef.APIDefinition) {
	v.Enabled = api.VersionDefinition.Enabled
	v.Name = api.VersionDefinition.Name
	v.Default = api.VersionDefinition.Default
	v.Location = api.VersionDefinition.Location
	v.Key = api.VersionDefinition.Key
	v.Versions = []VersionToID{}
	for vName, apiID := range api.VersionDefinition.Versions {
		v.Versions = append(v.Versions, VersionToID{vName, apiID})
	}

	sort.Slice(v.Versions, func(i, j int) bool {
		return v.Versions[i].Name < v.Versions[j].Name
	})

	if ShouldOmit(v.Versions) {
		v.Versions = nil
	}

	v.StripVersioningData = api.VersionDefinition.StripVersioningData
}

// ExtractTo extracts *Versioning into *apidef.APIDefinition.
func (v *Versioning) ExtractTo(api *apidef.APIDefinition) {
	api.VersionDefinition.Enabled = v.Enabled
	api.VersionDefinition.Name = v.Name
	api.VersionDefinition.Default = v.Default
	api.VersionDefinition.Location = v.Location
	api.VersionDefinition.Key = v.Key
	if api.VersionDefinition.Versions == nil {
		api.VersionDefinition.Versions = make(map[string]string)
	}

	for _, val := range v.Versions {
		api.VersionDefinition.Versions[val.Name] = val.ID
	}

	api.VersionDefinition.StripVersioningData = v.StripVersioningData
}

// VersionToID contains a single mapping from a version name into an API ID.
type VersionToID struct {
	// Name contains the user chosen version name, e.g. `v1` or similar.
	Name string `bson:"name" json:"name"`
	// ID is the API ID for the version set in Name.
	ID string `bson:"id" json:"id"`
}
