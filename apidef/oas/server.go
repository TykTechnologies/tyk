package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

// Server contains the configuration related to the OAS API definition.
type Server struct {
	// ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on,
	// that match this path will have the rules defined in the API definition applied.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required

	// Slug is the Tyk Cloud equivalent of listen path.
	// Tyk classic API definition: `slug`
	Slug string `bson:"slug,omitempty" json:"slug,omitempty"`

	// Authentication contains the configurations related to authentication to the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// ClientCertificates contains the configurations related to static mTLS.
	ClientCertificates *ClientCertificates `bson:"clientCertificates,omitempty" json:"clientCertificates,omitempty"`

	// GatewayTags contains segment tags to configure which GWs your APIs connect to.
	GatewayTags *GatewayTags `bson:"gatewayTags,omitempty" json:"gatewayTags,omitempty"`

	// CustomDomain is the domain to bind this API to.
	//
	// Tyk classic API definition: `domain`
	CustomDomain *Domain `bson:"customDomain,omitempty" json:"customDomain,omitempty"`
}

// Fill fills *Server from apidef.APIDefinition.
func (s *Server) Fill(api apidef.APIDefinition) {
	s.ListenPath.Fill(api)
	s.Slug = api.Slug

	if s.ClientCertificates == nil {
		s.ClientCertificates = &ClientCertificates{}
	}

	s.ClientCertificates.Fill(api)
	if ShouldOmit(s.ClientCertificates) {
		s.ClientCertificates = nil
	}

	if s.GatewayTags == nil {
		s.GatewayTags = &GatewayTags{}
	}
	s.GatewayTags.Fill(api)
	if ShouldOmit(s.GatewayTags) {
		s.GatewayTags = nil
	}

	if s.CustomDomain == nil {
		s.CustomDomain = &Domain{}
	}

	s.CustomDomain.Fill(api)
	if ShouldOmit(s.CustomDomain) {
		s.CustomDomain = nil
	}
}

// ExtractTo extracts *Server into *apidef.APIDefinition.
func (s *Server) ExtractTo(api *apidef.APIDefinition) {
	s.ListenPath.ExtractTo(api)
	api.Slug = s.Slug

	if s.ClientCertificates != nil {
		s.ClientCertificates.ExtractTo(api)
	}
	if s.GatewayTags != nil {
		s.GatewayTags.ExtractTo(api)
	}

	if s.CustomDomain != nil {
		s.CustomDomain.ExtractTo(api)
	}
}

// ListenPath represents the path the server should listen on.
type ListenPath struct {
	// Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.
	// Tyk classic API definition: `proxy.listen_path`
	Value string `bson:"value" json:"value"` // required
	// Strip removes the inbound listen path in the outgoing request. e.g. `http://acme.com/httpbin/get` where `httpbin`
	// is the listen path. The `httpbin` listen path which is used to identify the API loaded in Tyk is removed,
	// and the outbound request would be `http://httpbin.org/get`.
	// Tyk classic API definition: `proxy.strip_listen_path`
	Strip bool `bson:"strip,omitempty" json:"strip,omitempty"`
}

// Fill fills *ListenPath from apidef.APIDefinition.
func (lp *ListenPath) Fill(api apidef.APIDefinition) {
	lp.Value = api.Proxy.ListenPath
	lp.Strip = api.Proxy.StripListenPath
}

// ExtractTo extracts *ListenPath into *apidef.APIDefinition.
func (lp *ListenPath) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.ListenPath = lp.Value
	api.Proxy.StripListenPath = lp.Strip
}

// ClientCertificates holds a list of client certificates which are allowed to make requests against the server.
type ClientCertificates struct {
	// Enabled enables static mTLS for the API.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Allowlist is the list of client certificates which are allowed.
	Allowlist []string `bson:"allowlist" json:"allowlist"`
}

// Fill fills *ClientCertificates from apidef.APIDefinition.
func (cc *ClientCertificates) Fill(api apidef.APIDefinition) {
	cc.Enabled = api.UseMutualTLSAuth
	cc.Allowlist = api.ClientCertificates
}

// ExtractTo extracts *ClientCertificates into *apidef.APIDefinition.
func (cc *ClientCertificates) ExtractTo(api *apidef.APIDefinition) {
	api.UseMutualTLSAuth = cc.Enabled
	api.ClientCertificates = cc.Allowlist
}

// GatewayTags holds a list of segment tags that should apply for a gateway.
type GatewayTags struct {
	// Enabled enables use of segment tags.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Tags is a list of segment tags
	Tags []string `bson:"tags" json:"tags"`
}

// Fill fills *GatewayTags from apidef.APIDefinition.
func (gt *GatewayTags) Fill(api apidef.APIDefinition) {
	gt.Enabled = !api.TagsDisabled
	gt.Tags = api.Tags
}

// ExtractTo extracts *GatewayTags into *apidef.APIDefinition.
func (gt *GatewayTags) ExtractTo(api *apidef.APIDefinition) {
	api.TagsDisabled = !gt.Enabled
	api.Tags = gt.Tags
}

// Domain holds the configuration of the domain name the server should listen on.
type Domain struct {
	// Enabled allow/disallow the usage of the domain.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of the domain.
	Name string `bson:"name" json:"name"`
}

// ExtractTo extracts *Domain into *apidef.APIDefinition.
func (cd *Domain) ExtractTo(api *apidef.APIDefinition) {
	api.DomainDisabled = !cd.Enabled
	api.Domain = cd.Name
}

// Fill fills *Domain from apidef.APIDefinition.
func (cd *Domain) Fill(api apidef.APIDefinition) {
	cd.Enabled = !api.DomainDisabled
	cd.Name = api.Domain
}
