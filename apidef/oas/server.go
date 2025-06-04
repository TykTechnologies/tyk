package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

// Server contains the configuration that sets Tyk up to receive requests from the client applications.
type Server struct {
	// ListenPath is the base path on Tyk to which requests for this API should
	// be sent. Tyk listens for any requests coming into the host at this
	// path, on the port that Tyk is configured to run on and processes these
	// accordingly.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required

	// Authentication contains the configurations that manage how clients can authenticate with Tyk to access the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
	ClientCertificates *ClientCertificates `bson:"clientCertificates,omitempty" json:"clientCertificates,omitempty"`

	// GatewayTags contain segment tags to indicate which Gateways your upstream service is connected to (and hence where to deploy the API).
	GatewayTags *GatewayTags `bson:"gatewayTags,omitempty" json:"gatewayTags,omitempty"`

	// CustomDomain is the domain to bind this API to. This enforces domain matching for client requests.
	//
	// Tyk classic API definition: `domain`
	CustomDomain *Domain `bson:"customDomain,omitempty" json:"customDomain,omitempty"`

	// DetailedActivityLogs configures detailed analytics recording.
	DetailedActivityLogs *DetailedActivityLogs `bson:"detailedActivityLogs,omitempty" json:"detailedActivityLogs,omitempty"`

	// DetailedTracing enables OpenTelemetry's detailed tracing for this API.
	//
	// Tyk classic API definition: `detailed_tracing`
	DetailedTracing *DetailedTracing `bson:"detailedTracing,omitempty" json:"detailedTracing,omitempty"`

	// EventHandlers contains the configuration related to Tyk Events.
	//
	// Tyk classic API definition: `event_handlers`
	EventHandlers EventHandlers `bson:"eventHandlers,omitempty" json:"eventHandlers,omitempty"`

	// IPAccessControl configures IP access control for this API.
	//
	// Tyk classic API definition: `allowed_ips` and `blacklisted_ips`.
	IPAccessControl *IPAccessControl `bson:"ipAccessControl,omitempty" json:"ipAccessControl,omitempty"`

	// BatchProcessing contains configuration settings to enable or disable batch request support for the API.
	//
	// Tyk classic API definition: `enable_batch_request_support`.
	BatchProcessing *BatchProcessing `bson:"batchProcessing,omitempty" json:"batchProcessing,omitempty"`

	// Protocol configures the HTTP protocol used by the API.
	// Possible values are:
	// - "http": Standard HTTP/1.1 protocol
	// - "http2": HTTP/2 protocol with TLS
	// - "h2c": HTTP/2 protocol without TLS (cleartext).
	//
	// Tyk classic API definition: `protocol`.
	Protocol string `bson:"protocol,omitempty" json:"protocol,omitempty"`
	// Port Setting this value will change the port that Tyk listens on. Default: 8080.
	//
	// Tyk classic API definition: `listen_port`.
	Port int `bson:"port,omitempty" json:"port,omitempty"`
}

// Fill fills *Server from apidef.APIDefinition.
func (s *Server) Fill(api apidef.APIDefinition) {
	s.Protocol = api.Protocol
	s.Port = api.ListenPort

	s.ListenPath.Fill(api)

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

	if s.DetailedActivityLogs == nil {
		s.DetailedActivityLogs = &DetailedActivityLogs{}
	}

	s.DetailedActivityLogs.Fill(api)
	if ShouldOmit(s.DetailedActivityLogs) {
		s.DetailedActivityLogs = nil
	}

	if s.DetailedTracing == nil {
		s.DetailedTracing = &DetailedTracing{}
	}
	s.DetailedTracing.Fill(api)
	if ShouldOmit(s.DetailedTracing) {
		s.DetailedTracing = nil
	}

	if s.EventHandlers == nil {
		s.EventHandlers = EventHandlers{}
	}
	s.EventHandlers.Fill(api)
	if ShouldOmit(s.EventHandlers) {
		s.EventHandlers = nil
	}

	s.fillIPAccessControl(api)
	s.fillBatchProcessing(api)
}

// ExtractTo extracts *Server into *apidef.APIDefinition.
func (s *Server) ExtractTo(api *apidef.APIDefinition) {
	api.Protocol = s.Protocol
	api.ListenPort = s.Port
	s.ListenPath.ExtractTo(api)

	if s.ClientCertificates == nil {
		s.ClientCertificates = &ClientCertificates{}
		defer func() {
			s.ClientCertificates = nil
		}()
	}

	s.ClientCertificates.ExtractTo(api)

	if s.GatewayTags == nil {
		s.GatewayTags = &GatewayTags{}
		defer func() {
			s.GatewayTags = nil
		}()
	}

	s.GatewayTags.ExtractTo(api)

	if s.CustomDomain == nil {
		s.CustomDomain = &Domain{}
		defer func() {
			s.CustomDomain = nil
		}()
	}

	s.CustomDomain.ExtractTo(api)

	if s.DetailedActivityLogs == nil {
		s.DetailedActivityLogs = &DetailedActivityLogs{}
		defer func() {
			s.DetailedActivityLogs = nil
		}()
	}

	s.DetailedActivityLogs.ExtractTo(api)

	if s.DetailedTracing == nil {
		s.DetailedTracing = &DetailedTracing{}
		defer func() {
			s.DetailedTracing = nil
		}()
	}

	s.DetailedTracing.ExtractTo(api)

	if s.EventHandlers == nil {
		s.EventHandlers = EventHandlers{}
		defer func() {
			s.EventHandlers = nil
		}()
	}

	s.EventHandlers.ExtractTo(api)

	s.extractIPAccessControlTo(api)
	s.extractBatchProcessingTo(api)
}

// ListenPath is the base path on Tyk to which requests for this API
// should be sent. Tyk listens out for any requests coming into the host at
// this path, on the port that Tyk is configured to run on and processes
// these accordingly.
type ListenPath struct {
	// Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.
	// Tyk classic API definition: `proxy.listen_path`
	Value string `bson:"value" json:"value"` // required

	// Strip removes the inbound listen path (as accessed by the client) when generating the outbound request for the upstream service.
	//
	// For example, consider the scenario where the Tyk base address is `http://acme.com/', the listen path is `example/` and the upstream URL is `http://httpbin.org/`:
	//
	// - If the client application sends a request to `http://acme.com/example/get` then the request will be proxied to `http://httpbin.org/example/get`
	// - If stripListenPath is set to `true`, the `example` listen path is removed and the request would be proxied to `http://httpbin.org/get`.
	//
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

// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
type ClientCertificates struct {
	// Enabled activates static mTLS for the API.
	//
	// Tyk classic API definition: `use_mutual_tls_auth`.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Allowlist is the list of client certificates which are allowed.
	//
	// Tyk classic API definition: `client_certificates`.
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
	// Enabled activates use of segment tags.
	//
	// Tyk classic API definition: `tags_disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Tags contains a list of segment tags.
	//
	// Tyk classic API definition: `tags`.
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
	//
	// Tyk classic API definition: `domain_disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of the domain.
	//
	// Tyk classic API definition: `domain`.
	Name string `bson:"name" json:"name"`
	// Certificates defines a field for specifying certificate IDs or file paths
	// that the Gateway can utilise to dynamically load certificates for your custom domain.
	//
	// Tyk classic API definition: `certificates`
	Certificates []string `bson:"certificates,omitempty" json:"certificates,omitempty"`
}

// ExtractTo extracts *Domain into *apidef.APIDefinition.
func (cd *Domain) ExtractTo(api *apidef.APIDefinition) {
	api.DomainDisabled = !cd.Enabled
	api.Domain = cd.Name
	api.Certificates = cd.Certificates
}

// Fill fills *Domain from apidef.APIDefinition.
func (cd *Domain) Fill(api apidef.APIDefinition) {
	cd.Enabled = !api.DomainDisabled
	cd.Name = api.Domain
	cd.Certificates = api.Certificates
}

// DetailedActivityLogs holds the configuration related to recording detailed analytics.
type DetailedActivityLogs struct {
	// Enabled activates detailed activity logs.
	//
	// Tyk classic API definition: `enable_detailed_recording`
	Enabled bool `bson:"enabled" json:"enabled"`
}

// ExtractTo extracts *DetailedActivityLogs into *apidef.APIDefinition.
func (d *DetailedActivityLogs) ExtractTo(api *apidef.APIDefinition) {
	api.EnableDetailedRecording = d.Enabled
}

// Fill fills *DetailedActivityLogs from apidef.APIDefinition.
func (d *DetailedActivityLogs) Fill(api apidef.APIDefinition) {
	d.Enabled = api.EnableDetailedRecording
}

// DetailedTracing holds the configuration of the detailed tracing.
type DetailedTracing struct {
	// Enabled activates detailed tracing.
	//
	// Tyk classic API definition: `detailed_tracing`.
	Enabled bool `bson:"enabled" json:"enabled"`
}

// Fill fills *DetailedTracing from apidef.APIDefinition.
func (dt *DetailedTracing) Fill(api apidef.APIDefinition) {
	dt.Enabled = api.DetailedTracing
}

// ExtractTo extracts *DetailedTracing into *apidef.APIDefinition.
func (dt *DetailedTracing) ExtractTo(api *apidef.APIDefinition) {
	api.DetailedTracing = dt.Enabled
}

// IPAccessControl represents IP access control configuration.
type IPAccessControl struct {
	// Enabled indicates whether IP access control is enabled.
	//
	// Tyk classic API definition: `ip_access_control_disabled` (negated).
	Enabled bool `bson:"enabled" json:"enabled"`

	// Allow is a list of allowed IP addresses or CIDR blocks (e.g. "192.168.1.0/24").
	// Note that if an IP address is present in both Allow and Block, the Block rule will take precedence.
	//
	// Tyk classic API definition: `allowed_ips`.
	Allow []string `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block is a list of blocked IP addresses or CIDR blocks (e.g. "192.168.1.100/32").
	// If an IP address is present in both Allow and Block, the Block rule will take precedence.
	//
	// Tyk classic API definition: `blacklisted_ips`.
	Block []string `bson:"block,omitempty" json:"block,omitempty"`
}

// Fill fills *IPAccessControl from apidef.APIDefinition.
func (i *IPAccessControl) Fill(api apidef.APIDefinition) {
	i.Enabled = !api.IPAccessControlDisabled
	i.Block = api.BlacklistedIPs
	i.Allow = api.AllowedIPs
}

// ExtractTo extracts *IPAccessControl into *apidef.APIDefinition.
func (i *IPAccessControl) ExtractTo(api *apidef.APIDefinition) {
	api.IPAccessControlDisabled = !i.Enabled
	api.BlacklistedIPs = i.Block
	api.AllowedIPs = i.Allow
}

func (s *Server) fillIPAccessControl(api apidef.APIDefinition) {
	if s.IPAccessControl == nil {
		s.IPAccessControl = &IPAccessControl{}
	}

	s.IPAccessControl.Fill(api)
	if ShouldOmit(s.IPAccessControl) {
		s.IPAccessControl = nil
	}
}

func (s *Server) extractIPAccessControlTo(api *apidef.APIDefinition) {
	if s.IPAccessControl == nil {
		s.IPAccessControl = &IPAccessControl{}
		defer func() {
			s.IPAccessControl = nil
		}()
	}

	s.IPAccessControl.ExtractTo(api)
}

// BatchProcessing represents the configuration for enabling or disabling batch request support for an API.
type BatchProcessing struct {
	// Enabled determines whether batch request support is enabled or disabled for the API.
	//
	// Tyk classic API definition: `enable_batch_request_support`.
	Enabled bool `bson:"enabled" json:"enabled"` // required
}

// Fill updates the BatchProcessing configuration based on the EnableBatchRequestSupport value from the given APIDefinition.
func (b *BatchProcessing) Fill(api apidef.APIDefinition) {
	b.Enabled = api.EnableBatchRequestSupport
}

// ExtractTo copies the Enabled state of BatchProcessing into the EnableBatchRequestSupport field of the provided APIDefinition.
func (b *BatchProcessing) ExtractTo(api *apidef.APIDefinition) {
	api.EnableBatchRequestSupport = b.Enabled
}

func (s *Server) fillBatchProcessing(api apidef.APIDefinition) {
	if s.BatchProcessing == nil {
		s.BatchProcessing = &BatchProcessing{}
	}

	s.BatchProcessing.Fill(api)

	if ShouldOmit(s.BatchProcessing) {
		s.BatchProcessing = nil
	}
}

func (s *Server) extractBatchProcessingTo(api *apidef.APIDefinition) {
	if s.BatchProcessing == nil {
		s.BatchProcessing = &BatchProcessing{}
		defer func() {
			s.BatchProcessing = nil
		}()
	}

	s.BatchProcessing.ExtractTo(api)
}
