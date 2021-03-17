package oas

import (
	"gopkg.in/mgo.v2/bson"

	"github.com/TykTechnologies/tyk/apidef"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

type XTykAPIGateway struct {
	Info       Info        `bson:"info" json:"info"`         // required
	Upstream   Upstream    `bson:"upstream" json:"upstream"` // required
	Server     Server      `bson:"server" json:"server"`     // required
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
}

type Info struct {
	ID    string        `bson:"id" json:"id,omitempty"`       // just required on database
	DBID  bson.ObjectId `bson:"dbID" json:"dbID,omitempty"`   // just required on database
	OrgID string        `bson:"orgID" json:"orgID,omitempty"` // just required on database
	Name  string        `bson:"name" json:"name"`             // required
	State State         `bson:"state" json:"state"`           // required
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
	Active   bool `bson:"active" json:"active"` // required
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
