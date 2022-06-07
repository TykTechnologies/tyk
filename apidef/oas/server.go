package oas

import (
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

type Server struct {
	// ListenPath represents the path to listen on. Any requests coming into the host, on the port that Tyk is configured to run on,
	// that match this path will have the rules defined in the API Definition applied.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required
	// Slug is the Tyk Cloud equivalent of listen path.
	// Old API Definition: `slug`
	Slug string `bson:"slug,omitempty" json:"slug,omitempty"`
	// Authentication contains the configurations related to authentication to the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`
	// ClientCertificates contains the configurations related to static mTLS.
	ClientCertificates *ClientCertificates `bson:"clientCertificates,omitempty" json:"clientCertificates,omitempty"`
	// GatewayTags contains segment tags to configure which GWs your APIs connect to
	GatewayTags *GatewayTags `bson:"gatewayTags,omitempty" json:"gatewayTags,omitempty"`
	// CustomDomain is the domain to bind this API to.
	// Old API Definition: `domain`
	CustomDomain *Domain `bson:"customDomain,omitempty" json:"customDomain,omitempty"`
}

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

	if s.CustomDomain != nil {
		s.CustomDomain.Fill(api)
	}
}

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

type ClientCertificates struct {
	// Enabled enables static mTLS for the API.
	Enabled bool `bson:"enabled,omitempty" json:"enabled,omitempty"`
	// AllowList is the list of client certificates which are allowed.
	Allowlist []string `bson:"allowlist" json:"allowlist"`
}

func (cc *ClientCertificates) Fill(api apidef.APIDefinition) {
	cc.Enabled = api.UseMutualTLSAuth
	cc.Allowlist = api.ClientCertificates
}

func (cc *ClientCertificates) ExtractTo(api *apidef.APIDefinition) {
	api.UseMutualTLSAuth = cc.Enabled
	api.ClientCertificates = cc.Allowlist
}

type GatewayTags struct {
	// Enabled enables use of segment tags.
	Enabled bool `bson:"enabled,omitempty" json:"enabled,omitempty"`
	// Tags is a list of segment tags
	Tags []string `bson:"tags" json:"tags"`
}

func (gt *GatewayTags) Fill(api apidef.APIDefinition) {
	gt.Enabled = api.EnableTags
	gt.Tags = api.Tags
}

func (gt *GatewayTags) ExtractTo(api *apidef.APIDefinition) {
	api.EnableTags = gt.Enabled
	api.Tags = gt.Tags
}

type Certificate struct {
	Domain string `bson:"domain" json:"domain"`
	Cert   string `bson:"certificate" json:"certificate"`
}

type Certificates []Certificate

func (c Certificates) Fill(upstreamCerts map[string]string) {
	i := 0
	for domain, cert := range upstreamCerts {
		c[i] = Certificate{Domain: domain, Cert: cert}
		i++
	}
}

func (c Certificates) ExtractTo(upstreamCerts map[string]string) {
	for _, cert := range c {
		upstreamCerts[cert.Domain] = cert.Cert
	}
}

type PinnedPublicKey struct {
	Domain string   `bson:"domain" json:"domain"`
	List   []string `bson:"list" json:"list"`
}

type PinnedPublicKeys []PinnedPublicKey

func (ppk PinnedPublicKeys) Fill(publicKeys map[string]string) {
	domains := make([]string, len(publicKeys))

	i := 0
	for domain := range publicKeys {
		domains[i] = domain
		i++
	}

	sort.Slice(domains, func(i, j int) bool {
		return domains[i] < domains[j]
	})

	i = 0
	for _, domain := range domains {
		ppk[i] = PinnedPublicKey{Domain: domain, List: strings.Split(strings.ReplaceAll(publicKeys[domain], " ", ""), ",")}
		i++
	}
}

func (ppk PinnedPublicKeys) ExtractTo(publicKeys map[string]string) {
	for _, publicKey := range ppk {
		publicKeys[publicKey.Domain] = strings.Join(publicKey.List, ",")
	}
}

type Domain struct {
	// Enabled allow/disallow the usage of the domain.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Name is the name of the domain.
	Name string `json:"name" bson:"name"`
}

func (cd *Domain) ExtractTo(api *apidef.APIDefinition) {
	if !cd.Enabled && cd.Name == "" {
		// nothing was configured
		return
	}
	api.DomainDisabled = !cd.Enabled
	api.Domain = cd.Name
}

func (cd *Domain) Fill(api apidef.APIDefinition) {
	if !api.DomainDisabled && api.Domain == "" {
		// nothing was configured.
		return
	}
	cd.Enabled = !api.DomainDisabled
	cd.Name = api.Domain
}
