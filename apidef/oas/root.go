package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

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

func (x *XTykAPIGateway) ExtractTo(api *apidef.APIDefinition) {
	x.Info.ExtractTo(api)
	x.Upstream.ExtractTo(api)
	x.Server.ExtractTo(api)

	if x.Middleware != nil {
		x.Middleware.ExtractTo(api)
	}
}

type Info struct {
	// ID is the unique ID of the API.
	// Old API Definition: `api_id`
	ID string `bson:"id" json:"id,omitempty"`
	// DBID is the unique database ID of the API.
	// Old API Definition: `id`
	DBID apidef.ObjectId `bson:"dbId" json:"dbId,omitempty"`
	// OrgID is the ID of the organisation which the API belongs to.
	// Old API Definition: `org_id`
	OrgID string `bson:"orgId" json:"orgId,omitempty"`
	// Name is the name of the API.
	// Old API Definition: `name`
	Name string `bson:"name" json:"name"` // required
	// State contains the configurations related to the state of the API.
	State      State       `bson:"state" json:"state"` // required
	Versioning *Versioning `bson:"versioning,omitempty" json:"versioning,omitempty"`
}

func (i *Info) Fill(api apidef.APIDefinition) {
	i.ID = api.APIID
	i.DBID = api.Id
	i.OrgID = api.OrgID
	i.Name = api.Name
	i.State.Fill(api)

	if i.Versioning == nil {
		i.Versioning = &Versioning{}
	}

	i.Versioning.Fill(api)
	if ShouldOmit(i.Versioning) {
		i.Versioning = nil
	}
}

func (i *Info) ExtractTo(api *apidef.APIDefinition) {
	api.APIID = i.ID
	api.Id = i.DBID
	api.OrgID = i.OrgID
	api.Name = i.Name
	i.State.ExtractTo(api)

	if i.Versioning != nil {
		i.Versioning.ExtractTo(api)
	} else {
		api.VersionData.NotVersioned = true
	}
}

type State struct {
	// Active enables the API.
	// Old API Definition: `active`
	Active bool `bson:"active" json:"active"` // required
	// Internal makes the API accessible only internally.
	// Old API Definition: `internal`
	Internal bool `bson:"internal,omitempty" json:"internal,omitempty"`
}

func (s *State) Fill(api apidef.APIDefinition) {
	s.Active = api.Active
	s.Internal = api.Internal
}

func (s *State) ExtractTo(api *apidef.APIDefinition) {
	api.Active = s.Active
	api.Internal = s.Internal
}

type Versioning struct {
	Enabled   bool              `bson:"enabled" json:"enabled"` // required
	Versions  map[string]string `bson:"versions,omitempty" json:"versions,omitempty"`
	Location  string            `bson:"location,omitempty" json:"location,omitempty"`
	Key       string            `bson:"key,omitempty" json:"key,omitempty"`
	StripPath bool              `bson:"stripPath,omitempty" json:"stripPath,omitempty"`
}

func (v *Versioning) Fill(api apidef.APIDefinition) {
	v.Enabled = !api.VersionData.NotVersioned
	v.Versions = make(map[string]string)

	for vName, ver := range api.VersionData.Versions {
		if vName == "Default" {
			continue
		}
		v.Versions[vName] = ver.APIID
	}

	if ShouldOmit(v.Versions) {
		v.Versions = nil
	}

	v.Location = api.VersionDefinition.Location
	v.Key = api.VersionDefinition.Key
	v.StripPath = api.VersionDefinition.StripPath
}

func (v *Versioning) ExtractTo(api *apidef.APIDefinition) {
	api.VersionData.NotVersioned = !v.Enabled
	if api.VersionData.Versions == nil {
		api.VersionData.Versions = make(map[string]apidef.VersionInfo)
	}

	for vName, apiID := range v.Versions {
		api.VersionData.Versions[vName] = apidef.VersionInfo{
			APIID: apiID,
		}
	}

	api.VersionDefinition.Location = v.Location
	api.VersionDefinition.Key = v.Key
	api.VersionDefinition.StripPath = v.StripPath
}
