package oas

import "github.com/TykTechnologies/tyk/apidef"

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
