package oas

import (
	"reflect"

	"github.com/TykTechnologies/tyk/apidef"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

type EndpointMetaType int

const (
	whiteList EndpointMetaType = 0
	blackList EndpointMetaType = 1
	ignored   EndpointMetaType = 2
)

type XTykAPIGateway struct {
	Info       Info        `bson:"info" json:"info"`         // required
	Upstream   Upstream    `bson:"upstream" json:"upstream"` // required
	Server     Server      `bson:"server" json:"server"`     // required
	Middleware *Middleware `bson:"middleware" json:"middleware"`
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
	ID    string `bson:"id" json:"id,omitempty"` // just required on database
	Name  string `bson:"name" json:"name"`       // required
	State State  `bson:"state" json:"state"`     // required
}

func (i *Info) Fill(api apidef.APIDefinition) {
	i.ID = api.APIID
	i.Name = api.Name
	i.State.Fill(api)
}

func (i *Info) ExtractTo(api *apidef.APIDefinition) {
	api.APIID = i.ID
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

type Upstream struct {
	URL string `bson:"url" json:"url"` // required
}

func (u *Upstream) Fill(api apidef.APIDefinition) {
	u.URL = api.Proxy.TargetURL
}

func (u *Upstream) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.TargetURL = u.URL
}

type Server struct {
	ListenPath     ListenPath      `bson:"listenPath" json:"listenPath"` // required
	Slug           string          `bson:"slug,omitempty" json:"slug,omitempty"`
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`
}

func (s *Server) Fill(api apidef.APIDefinition) {
	s.ListenPath.Fill(api)
	s.Slug = api.Slug

	if s.Authentication == nil {
		s.Authentication = &Authentication{}
	}

	s.Authentication.Fill(api)
	if (*s.Authentication == Authentication{}) {
		s.Authentication = nil
	}
}

func (s *Server) ExtractTo(api *apidef.APIDefinition) {
	s.ListenPath.ExtractTo(api)
	api.Slug = s.Slug

	if s.Authentication != nil {
		s.Authentication.ExtractTo(api)
	} else {
		api.UseKeylessAccess = true
	}
}

type ListenPath struct {
	Value string `bson:"value" json:"value"` // required
	Strip bool   `bson:"strip,omitempty" json:"strip,omitempty"`
}

func (lp *ListenPath) Fill(api apidef.APIDefinition) {
	lp.Value = api.Proxy.ListenPath
	lp.Strip = api.Proxy.StripListenPath
}

func (lp *ListenPath) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.ListenPath = lp.Value
	api.Proxy.StripListenPath = lp.Strip
}

type Middleware struct {
	Global *Global `bson:"global,omitempty" json:"global,omitempty"`
}

func (m *Middleware) Fill(api apidef.APIDefinition) {
	if m.Global == nil {
		m.Global = &Global{}
	}

	m.Global.Fill(api)
	if reflect.DeepEqual(m.Global, &Global{}) {
		m.Global = nil
	}
}

func (m *Middleware) ExtractTo(api *apidef.APIDefinition) {
	if m.Global != nil {
		m.Global.ExtractTo(api)
	}
}
