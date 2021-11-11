package oas

import "github.com/TykTechnologies/tyk/apidef"

type Server struct {
	// ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on,
	// that match this path will have the rules defined in the API Definition applied.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required
	// Slug is the Tyk Cloud equivalent of listen path.
	// Old API Definition: `slug`
	Slug string `bson:"slug,omitempty" json:"slug,omitempty"`
	// Authentication contains the configurations related to authentication to the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`
}

func (s *Server) Fill(api apidef.APIDefinition) {
	s.ListenPath.Fill(api)
	s.Slug = api.Slug

	if s.Authentication == nil {
		s.Authentication = &Authentication{}
	}

	s.Authentication.Fill(api)
	if ShouldOmit(s.Authentication) {
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
	// Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.
	// Old API Definition: `proxy.listen_path`
	Value string `bson:"value" json:"value"` // required
	// Strip removes the inbound listen path in the outgoing request. e.g. `http://acme.com/httpbin/get` where `httpbin`
	// is the listen path. The `httpbin` listen path which is used to identify the API loaded in Tyk is removed,
	// and the outbound request would be `http://httpbin.org/get`.
	// Old API Definition: `proxy.strip_listen_path`
	Strip bool `bson:"strip,omitempty" json:"strip,omitempty"`
}

func (lp *ListenPath) Fill(api apidef.APIDefinition) {
	lp.Value = api.Proxy.ListenPath
	lp.Strip = api.Proxy.StripListenPath
}

func (lp *ListenPath) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.ListenPath = lp.Value
	api.Proxy.StripListenPath = lp.Strip
}
