package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

type XTykAPIGateway struct {
	// Info contains the main metadata about the API definition.
	Info     Info     `bson:"info" json:"info"`         // required
	// Upstream contains the configurations related to the upstream.
	Upstream Upstream `bson:"upstream" json:"upstream"` // required
	// Server contains the configurations related to the server.
	Server     Server      `bson:"server" json:"server"` // required
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
	if (*x.Middleware == Middleware{}) {
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

	// This is used to make API calls work before actual versioning implementation.
	api.VersionData.DefaultVersion = "Default"
	api.VersionData.NotVersioned = true
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {},
	}
}

type Info struct {
	// ID is the unique ID of the API.
	// Old API Definition: `api_id`
	ID string `bson:"id" json:"id,omitempty"`
	// DBID is the unique database ID of the API.
	// Old API Definition: `id`
	DBID  apidef.ObjectId `bson:"dbID" json:"dbID,omitempty"`
	// OrgID is the ID of the organisation which the API belongs to.
	// Old API Definition: `org_id`
	OrgID string          `bson:"orgID" json:"orgID,omitempty"`
	// Name is the name of the API.
	// Old API Definition: `name`
	Name  string          `bson:"name" json:"name"` // required
	// State contains the configurations related to the state of the API.
	State State `bson:"state" json:"state"` // required
}

func (i *Info) Fill(api apidef.APIDefinition) {
	i.ID = api.APIID
	i.DBID = api.Id
	i.OrgID = api.OrgID
	i.Name = api.Name
	i.State.Fill(api)
}

func (i *Info) ExtractTo(api *apidef.APIDefinition) {
	api.APIID = i.ID
	api.Id = i.DBID
	api.OrgID = i.OrgID
	api.Name = i.Name
	i.State.ExtractTo(api)
}

type State struct {
	// Active enables the API.
	// Old API Definition: `active`
	Active   bool `bson:"active" json:"active"` // required
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
