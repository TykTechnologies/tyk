package oas

import (
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/time"
)

// Upstream holds configuration for the upstream server to which Tyk should proxy requests.
type Upstream struct {
	// URL defines the upstream address (or target URL) to which requests should be proxied.
	// Tyk classic API definition: `proxy.target_url`
	URL string `bson:"url" json:"url"` // required

	// ServiceDiscovery contains the configuration related to Service Discovery.
	// Tyk classic API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`

	// Test contains the configuration related to uptime tests.
	Test *Test `bson:"test,omitempty" json:"test,omitempty"`

	// MutualTLS contains the configuration for establishing a mutual TLS connection between Tyk and the upstream server.
	MutualTLS *MutualTLS `bson:"mutualTLS,omitempty" json:"mutualTLS,omitempty"`

	// CertificatePinning contains the configuration related to certificate pinning.
	CertificatePinning *CertificatePinning `bson:"certificatePinning,omitempty" json:"certificatePinning,omitempty"`

	// RateLimit contains the configuration related to API level rate limit.
	RateLimit *RateLimit `bson:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Authentication contains the configuration related to upstream authentication.
	Authentication *UpstreamAuth `bson:"authentication,omitempty" json:"authentication,omitempty"`
}

// Fill fills *Upstream from apidef.APIDefinition.
func (u *Upstream) Fill(api apidef.APIDefinition) {
	u.URL = api.Proxy.TargetURL

	if u.ServiceDiscovery == nil {
		u.ServiceDiscovery = &ServiceDiscovery{}
	}

	u.ServiceDiscovery.Fill(api.Proxy.ServiceDiscovery)
	if ShouldOmit(u.ServiceDiscovery) {
		u.ServiceDiscovery = nil
	}

	if u.Test == nil {
		u.Test = &Test{}
	}

	u.Test.Fill(api.UptimeTests)
	if ShouldOmit(u.Test) {
		u.Test = nil
	}

	if u.MutualTLS == nil {
		u.MutualTLS = &MutualTLS{}
	}

	u.MutualTLS.Fill(api)
	if ShouldOmit(u.MutualTLS) {
		u.MutualTLS = nil
	}

	if u.CertificatePinning == nil {
		u.CertificatePinning = &CertificatePinning{}
	}

	u.CertificatePinning.Fill(api)
	if ShouldOmit(u.CertificatePinning) {
		u.CertificatePinning = nil
	}

	if u.RateLimit == nil {
		u.RateLimit = &RateLimit{}
	}

	u.RateLimit.Fill(api)
	if ShouldOmit(u.RateLimit) {
		u.RateLimit = nil
	}

	if u.Authentication == nil {
		u.Authentication = &UpstreamAuth{}
	}

	u.Authentication.Fill(api.UpstreamAuth)
	if ShouldOmit(u.Authentication) {
		u.Authentication = nil
	}
}

// ExtractTo extracts *Upstream into *apidef.APIDefinition.
func (u *Upstream) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.TargetURL = u.URL

	if u.ServiceDiscovery == nil {
		u.ServiceDiscovery = &ServiceDiscovery{}
		defer func() {
			u.ServiceDiscovery = nil
		}()
	}

	u.ServiceDiscovery.ExtractTo(&api.Proxy.ServiceDiscovery)

	if u.Test == nil {
		u.Test = &Test{}
		defer func() {
			u.Test = nil
		}()
	}

	u.Test.ExtractTo(&api.UptimeTests)

	if u.MutualTLS == nil {
		u.MutualTLS = &MutualTLS{}
		defer func() {
			u.MutualTLS = nil
		}()
	}

	u.MutualTLS.ExtractTo(api)

	if u.CertificatePinning == nil {
		u.CertificatePinning = &CertificatePinning{}
		defer func() {
			u.CertificatePinning = nil
		}()
	}

	u.CertificatePinning.ExtractTo(api)

	if u.RateLimit == nil {
		u.RateLimit = &RateLimit{}
		defer func() {
			u.RateLimit = nil
		}()
	}

	u.RateLimit.ExtractTo(api)

	if u.Authentication == nil {
		u.Authentication = &UpstreamAuth{}
		defer func() {
			u.Authentication = nil
		}()
	}

	u.Authentication.ExtractTo(&api.UpstreamAuth)
}

// ServiceDiscovery holds configuration required for service discovery.
type ServiceDiscovery struct {
	// Enabled activates Service Discovery.
	//
	// Tyk classic API definition: `service_discovery.use_discovery_service`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.
	// Tyk classic API definition: `service_discovery.query_endpoint`
	QueryEndpoint string `bson:"queryEndpoint,omitempty" json:"queryEndpoint,omitempty"`

	// DataPath is the namespace of the data path - where exactly in your service response the namespace can be found.
	// For example, if your service responds with:
	//
	// ```
	// {
	//  "action": "get",
	//  "node": {
	//    "key": "/services/single",
	//    "value": "http://httpbin.org:6000",
	//    "modifiedIndex": 6,
	//    "createdIndex": 6
	//  }
	// }
	// ```
	//
	// then your namespace would be `node.value`.
	//
	// Tyk classic API definition: `service_discovery.data_path`
	DataPath string `bson:"dataPath,omitempty" json:"dataPath,omitempty"`

	// UseNestedQuery enables the use of a combination of `dataPath` and `parentDataPath`.
	// It is necessary when the data lives within this string-encoded JSON object.
	//
	// ```
	// {
	//  "action": "get",
	//  "node": {
	//    "key": "/services/single",
	//    "value": "{"hostname": "http://httpbin.org", "port": "80"}",
	//    "modifiedIndex": 6,
	//    "createdIndex": 6
	//  }
	// }
	// ```
	//
	// Tyk classic API definition: `service_discovery.use_nested_query`
	UseNestedQuery bool `bson:"useNestedQuery,omitempty" json:"useNestedQuery,omitempty"`

	// ParentDataPath is the namespace of the where to find the nested
	// value if `useNestedQuery` is `true`. In the above example, it
	// would be `node.value`. You would change the `dataPath` setting
	// to be `hostname`, since this is where the host name data
	// resides in the JSON string. Tyk automatically assumes that
	// `dataPath` in this case is in a string-encoded JSON object and
	// will try to deserialize it.
	//
	// Tyk classic API definition: `service_discovery.parent_data_path`
	ParentDataPath string `bson:"parentDataPath,omitempty" json:"parentDataPath,omitempty"`

	// PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value
	// for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath` as
	// the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier
	// such as `/widgets/`). In the above example, the `portDataPath` would be `port`.
	//
	// Tyk classic API definition: `service_discovery.port_data_path`
	PortDataPath string `bson:"portDataPath,omitempty" json:"portDataPath,omitempty"`

	// UseTargetList should be set to `true` if you are using load balancing. Tyk will treat the data path as a list and
	// inject it into the target list of your API definition.
	//
	// Tyk classic API definition: `service_discovery.use_target_list`
	UseTargetList bool `bson:"useTargetList,omitempty" json:"useTargetList,omitempty"`

	// CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
	// Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that
	// failures are not recovered from quickly enough.
	//
	// Deprecated: The field is deprecated. Use `service_discovery` to configure service discovery cache options.
	//
	// Tyk classic API definition: `service_discovery.cache_timeout`
	CacheTimeout int64 `bson:"cacheTimeout,omitempty" json:"cacheTimeout,omitempty"`

	// Cache holds cache related flags.
	//
	// Tyk classic API definition:
	// - `service_discovery.cache_disabled`
	// - `service_discovery.cache_timeout`
	Cache *ServiceDiscoveryCache `bson:"cache,omitempty" json:"cache,omitempty"`

	// TargetPath is used to set a target path that will be appended to the
	// discovered endpoint, since many service discovery services only provide
	// host and port data. It is important to be able to target a specific
	// resource on that host. Setting this value will enable that.
	//
	// Tyk classic API definition: `service_discovery.target_path`
	TargetPath string `bson:"targetPath,omitempty" json:"targetPath,omitempty"`

	// EndpointReturnsList is set `true` when the response type is a list instead of an object.
	//
	// Tyk classic API definition: `service_discovery.endpoint_returns_list`
	EndpointReturnsList bool `bson:"endpointReturnsList,omitempty" json:"endpointReturnsList,omitempty"`
}

// ServiceDiscoveryCache holds configuration for caching ServiceDiscovery data.
type ServiceDiscoveryCache struct {
	// Enabled turns service discovery cache on or off.
	//
	// Tyk classic API definition: `service_discovery.cache_disabled`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// Timeout is the TTL for a cached object in seconds.
	//
	// Tyk classic API definition: `service_discovery.cache_timeout`
	Timeout int64 `bson:"timeout,omitempty" json:"timeout,omitempty"`
}

// CacheOptions returns the timeout value in effect and a bool if cache is enabled.
func (sd *ServiceDiscovery) CacheOptions() (int64, bool) {
	if sd.Cache != nil {
		return sd.Cache.Timeout, sd.Cache.Enabled
	}

	return sd.CacheTimeout, sd.CacheTimeout > 0
}

// Fill fills *ServiceDiscovery from apidef.ServiceDiscoveryConfiguration.
func (sd *ServiceDiscovery) Fill(serviceDiscovery apidef.ServiceDiscoveryConfiguration) {
	sd.Enabled = serviceDiscovery.UseDiscoveryService
	sd.EndpointReturnsList = serviceDiscovery.EndpointReturnsList
	sd.ParentDataPath = serviceDiscovery.ParentDataPath
	sd.QueryEndpoint = serviceDiscovery.QueryEndpoint
	sd.TargetPath = serviceDiscovery.TargetPath
	sd.UseTargetList = serviceDiscovery.UseTargetList
	sd.UseNestedQuery = serviceDiscovery.UseNestedQuery
	sd.DataPath = serviceDiscovery.DataPath
	sd.PortDataPath = serviceDiscovery.PortDataPath

	enabled := !serviceDiscovery.CacheDisabled
	timeout := serviceDiscovery.CacheTimeout

	sd.CacheTimeout = 0
	sd.Cache = &ServiceDiscoveryCache{
		Enabled: enabled,
		Timeout: timeout,
	}
	if ShouldOmit(sd.Cache) {
		sd.Cache = nil
	}
}

// ExtractTo extracts *ServiceDiscovery into *apidef.ServiceDiscoveryConfiguration.
func (sd *ServiceDiscovery) ExtractTo(serviceDiscovery *apidef.ServiceDiscoveryConfiguration) {
	serviceDiscovery.UseDiscoveryService = sd.Enabled
	serviceDiscovery.EndpointReturnsList = sd.EndpointReturnsList
	serviceDiscovery.ParentDataPath = sd.ParentDataPath
	serviceDiscovery.QueryEndpoint = sd.QueryEndpoint
	serviceDiscovery.TargetPath = sd.TargetPath
	serviceDiscovery.UseTargetList = sd.UseTargetList
	serviceDiscovery.UseNestedQuery = sd.UseNestedQuery
	serviceDiscovery.DataPath = sd.DataPath
	serviceDiscovery.PortDataPath = sd.PortDataPath

	timeout, enabled := sd.CacheOptions()
	serviceDiscovery.CacheTimeout = timeout
	serviceDiscovery.CacheDisabled = !enabled
}

// Test holds the test configuration for service discovery.
type Test struct {
	// ServiceDiscovery contains the configuration related to test Service Discovery.
	// Tyk classic API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`
}

// Fill fills *Test from apidef.UptimeTests.
func (t *Test) Fill(uptimeTests apidef.UptimeTests) {
	if t.ServiceDiscovery == nil {
		t.ServiceDiscovery = &ServiceDiscovery{}
	}

	t.ServiceDiscovery.Fill(uptimeTests.Config.ServiceDiscovery)
	if ShouldOmit(t.ServiceDiscovery) {
		t.ServiceDiscovery = nil
	}
}

// ExtractTo extracts *Test into *apidef.UptimeTests.
func (t *Test) ExtractTo(uptimeTests *apidef.UptimeTests) {
	if t.ServiceDiscovery == nil {
		t.ServiceDiscovery = &ServiceDiscovery{}
		defer func() {
			t.ServiceDiscovery = nil
		}()
	}

	t.ServiceDiscovery.ExtractTo(&uptimeTests.Config.ServiceDiscovery)
}

// MutualTLS contains the configuration for establishing a mutual TLS connection between Tyk and the upstream server.
type MutualTLS struct {
	// Enabled activates upstream mutual TLS for the API.
	// Tyk classic API definition: `upstream_certificates_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToCertificates maintains the mapping of domain to certificate.
	// Tyk classic API definition: `upstream_certificates`
	DomainToCertificates []DomainToCertificate `bson:"domainToCertificateMapping" json:"domainToCertificateMapping"`
}

// DomainToCertificate holds a single mapping of domain name into a certificate.
type DomainToCertificate struct {
	// Domain contains the domain name.
	Domain string `bson:"domain" json:"domain"`

	// Certificate contains the certificate mapped to the domain.
	Certificate string `bson:"certificate" json:"certificate"`
}

// Fill fills *MutualTLS from apidef.APIDefinition.
func (m *MutualTLS) Fill(api apidef.APIDefinition) {
	m.Enabled = !api.UpstreamCertificatesDisabled
	m.DomainToCertificates = make([]DomainToCertificate, len(api.UpstreamCertificates))

	i := 0
	for domain, cert := range api.UpstreamCertificates {
		m.DomainToCertificates[i] = DomainToCertificate{Domain: domain, Certificate: cert}
		i++
	}

	if ShouldOmit(m.DomainToCertificates) {
		api.UpstreamCertificates = nil
	}
}

// ExtractTo extracts *MutualTLS into *apidef.APIDefinition.
func (m *MutualTLS) ExtractTo(api *apidef.APIDefinition) {
	api.UpstreamCertificatesDisabled = !m.Enabled

	if len(m.DomainToCertificates) > 0 {
		api.UpstreamCertificates = make(map[string]string)
	} else {
		api.UpstreamCertificates = nil
	}

	for _, domainToCert := range m.DomainToCertificates {
		api.UpstreamCertificates[domainToCert.Domain] = domainToCert.Certificate
	}
}

// PinnedPublicKey contains a mapping from the domain name into a list of public keys.
type PinnedPublicKey struct {
	// Domain contains the domain name.
	Domain string `bson:"domain" json:"domain"`

	// PublicKeys contains a list of the public keys pinned to the domain name.
	PublicKeys []string `bson:"publicKeys" json:"publicKeys"`
}

// PinnedPublicKeys is a list of domains and pinned public keys for them.
type PinnedPublicKeys []PinnedPublicKey

// Fill fills *PinnerPublicKeys (slice) from publicKeys argument.
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
		ppk[i] = PinnedPublicKey{Domain: domain, PublicKeys: strings.Split(strings.ReplaceAll(publicKeys[domain], " ", ""), ",")}
		i++
	}
}

// ExtractTo extracts PinnedPublicKeys values into the publicKeys map.
func (ppk PinnedPublicKeys) ExtractTo(publicKeys map[string]string) {
	for _, publicKey := range ppk {
		publicKeys[publicKey.Domain] = strings.Join(publicKey.PublicKeys, ",")
	}
}

// CertificatePinning holds the configuration about mapping of domains to pinned public keys.
type CertificatePinning struct {
	// Enabled is a boolean flag, if set to `true`, it enables certificate pinning for the API.
	//
	// Tyk classic API definition: `certificate_pinning_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.
	//
	// Tyk classic API definition: `pinned_public_keys`
	DomainToPublicKeysMapping PinnedPublicKeys `bson:"domainToPublicKeysMapping" json:"domainToPublicKeysMapping"`
}

// Fill fills *CertificatePinning from apidef.APIDefinition.
func (cp *CertificatePinning) Fill(api apidef.APIDefinition) {
	cp.Enabled = !api.CertificatePinningDisabled

	if cp.DomainToPublicKeysMapping == nil {
		cp.DomainToPublicKeysMapping = make(PinnedPublicKeys, len(api.PinnedPublicKeys))
	}

	cp.DomainToPublicKeysMapping.Fill(api.PinnedPublicKeys)

	if ShouldOmit(cp.DomainToPublicKeysMapping) {
		cp.DomainToPublicKeysMapping = nil
	}
}

// ExtractTo extracts *CertficiatePinning into *apidef.APIDefinition.
func (cp *CertificatePinning) ExtractTo(api *apidef.APIDefinition) {
	api.CertificatePinningDisabled = !cp.Enabled

	if len(cp.DomainToPublicKeysMapping) > 0 {
		api.PinnedPublicKeys = make(map[string]string)
		cp.DomainToPublicKeysMapping.ExtractTo(api.PinnedPublicKeys)
	} else {
		api.PinnedPublicKeys = nil
	}
}

// RateLimit holds the configurations related to rate limit.
// The API-level rate limit applies a base-line limit on the frequency of requests to the upstream service for all endpoints. The frequency of requests is configured in two parts: the time interval and the number of requests that can be made during each interval.
// Tyk classic API definition: `global_rate_limit`.
type RateLimit struct {
	// Enabled activates API level rate limiting for this API.
	//
	// Tyk classic API definition: `!disable_rate_limit`.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Rate specifies the number of requests that can be passed to the upstream in each time interval (`per`).
	// This field sets the limit on the frequency of requests to ensure controlled
	// resource access or to prevent abuse. The rate is defined as an integer value.
	//
	// A higher value indicates a higher number of allowed requests in the given
	// time frame. For instance, if `Per` is set to `1m` (one minute), a Rate of `100`
	// means up to 100 requests can be made per minute.
	//
	// Tyk classic API definition: `global_rate_limit.rate`.
	Rate int `json:"rate" bson:"rate"`
	// Per defines the time interval for rate limiting using shorthand notation.
	// The value of Per is a string that specifies the interval in a compact form,
	// where hours, minutes and seconds are denoted by 'h', 'm' and 's' respectively.
	// Multiple units can be combined to represent the duration.
	//
	// Examples of valid shorthand notations:
	// - "1h"   : one hour
	// - "20m"  : twenty minutes
	// - "30s"  : thirty seconds
	// - "1m29s": one minute and twenty-nine seconds
	// - "1h30m" : one hour and thirty minutes
	//
	// An empty value is interpreted as "0s", implying no rate limiting interval, which disables the API-level rate limit.
	// It's important to format the string correctly, as invalid formats will
	// be considered as 0s/empty.
	//
	// Tyk classic API definition: `global_rate_limit.per`.
	Per ReadableDuration `json:"per" bson:"per"`
}

// Fill fills *RateLimit from apidef.APIDefinition.
func (r *RateLimit) Fill(api apidef.APIDefinition) {
	r.Enabled = !api.GlobalRateLimit.Disabled
	r.Rate = int(api.GlobalRateLimit.Rate)
	r.Per = ReadableDuration(time.Duration(api.GlobalRateLimit.Per) * time.Second)
}

// ExtractTo extracts *Ratelimit into *apidef.APIDefinition.
func (r *RateLimit) ExtractTo(api *apidef.APIDefinition) {
	api.GlobalRateLimit.Disabled = !r.Enabled
	api.GlobalRateLimit.Rate = float64(r.Rate)
	api.GlobalRateLimit.Per = r.Per.Seconds()
}

// RateLimitEndpoint carries same settings as RateLimit but for endpoints.
type RateLimitEndpoint RateLimit

// Fill fills *RateLimit from apidef.RateLimitMeta.
func (r *RateLimitEndpoint) Fill(api apidef.RateLimitMeta) {
	r.Enabled = !api.Disabled
	r.Rate = int(api.Rate)
	r.Per = ReadableDuration(time.Duration(api.Per) * time.Second)
}

// ExtractTo extracts *Ratelimit into *apidef.RateLimitMeta.
func (r *RateLimitEndpoint) ExtractTo(meta *apidef.RateLimitMeta) {
	meta.Disabled = !r.Enabled
	meta.Rate = float64(r.Rate)
	meta.Per = r.Per.Seconds()
}

// UpstreamAuth holds the configurations related to upstream API authentication.
type UpstreamAuth struct {
	// Enabled enables upstream API authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// BasicAuth holds the basic authentication configuration for upstream API authentication.
	BasicAuth *UpstreamBasicAuth `bson:"basicAuth,omitempty" json:"basicAuth,omitempty"`
	// OAuth contains the configuration for OAuth2 Client Credentials flow.
	OAuth *UpstreamOAuth `bson:"oauth,omitempty" json:"oauth,omitempty"`
}

// Fill fills *UpstreamAuth from apidef.UpstreamAuth.
func (u *UpstreamAuth) Fill(api apidef.UpstreamAuth) {
	u.Enabled = api.Enabled

	if u.BasicAuth == nil {
		u.BasicAuth = &UpstreamBasicAuth{}
	}
	u.BasicAuth.Fill(api.BasicAuth)
	if ShouldOmit(u.BasicAuth) {
		u.BasicAuth = nil
	}

	if u.OAuth == nil {
		u.OAuth = &UpstreamOAuth{}
	}
	u.OAuth.Fill(api.OAuth)
	if ShouldOmit(u.OAuth) {
		u.OAuth = nil
	}
}

// ExtractTo extracts *UpstreamAuth into *apidef.UpstreamAuth.
func (u *UpstreamAuth) ExtractTo(api *apidef.UpstreamAuth) {
	api.Enabled = u.Enabled

	if u.BasicAuth == nil {
		u.BasicAuth = &UpstreamBasicAuth{}
		defer func() {
			u.BasicAuth = nil
		}()
	}
	u.BasicAuth.ExtractTo(&api.BasicAuth)

	if u.OAuth == nil {
		u.OAuth = &UpstreamOAuth{}
		defer func() {
			u.OAuth = nil
		}()
	}
	u.OAuth.ExtractTo(&api.OAuth)
}

// UpstreamBasicAuth holds upstream basic authentication configuration.
type UpstreamBasicAuth struct {
	// Enabled enables upstream basic authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Header contains configurations for the header value.
	Header *AuthSource `bson:"header,omitempty" json:"header,omitempty"`
	// Username is the username to be used for upstream basic authentication.
	Username string `bson:"username" json:"username"`
	// Password is the password to be used for upstream basic authentication.
	Password string `bson:"password" json:"password"`
}

// Fill fills *UpstreamBasicAuth from apidef.UpstreamBasicAuth.
func (u *UpstreamBasicAuth) Fill(api apidef.UpstreamBasicAuth) {
	u.Enabled = api.Enabled
	u.Username = api.Username
	u.Password = api.Password

	if u.Header == nil {
		u.Header = &AuthSource{}
	}
	u.Header.Fill(api.Header.Enabled, api.Header.Name)
	if ShouldOmit(u.Header) {
		u.Header = nil
	}
}

// ExtractTo extracts *UpstreamBasicAuth into *apidef.UpstreamBasicAuth.
func (u *UpstreamBasicAuth) ExtractTo(api *apidef.UpstreamBasicAuth) {
	api.Enabled = u.Enabled
	api.Enabled = u.Enabled
	api.Username = u.Username
	api.Password = u.Password

	if u.Header == nil {
		u.Header = &AuthSource{}
		defer func() {
			u.Header = nil
		}()
	}
	u.Header.ExtractTo(&api.Header.Enabled, &api.Header.Name)
}

// UpstreamOAuth holds the configuration for OAuth2 Client Credentials flow.
type UpstreamOAuth struct {
	// Enabled activates upstream OAuth2 authentication.
	Enabled bool `bson:"enabled" json:"enabled"`
	// AllowedAuthorizeTypes specifies the allowed authorization types for upstream OAuth2 authentication.
	AllowedAuthorizeTypes []string `bson:"allowedAuthorizeTypes" json:"allowedAuthorizeTypes"`
	// ClientCredentials holds the configuration for OAuth2 Client Credentials flow.
	ClientCredentials *ClientCredentials `bson:"clientCredentials,omitempty" json:"clientCredentials,omitempty"`
	// PasswordAuthentication holds the configuration for upstream OAauth password authentication flow.
	PasswordAuthentication *PasswordAuthentication `bson:"password,omitempty" json:"password,omitempty"`
}

// PasswordAuthentication holds the configuration for upstream OAuth2 password authentication flow.
type PasswordAuthentication struct {
	ClientAuthData
	// Header holds the configuration for the custom header to be used for OAuth authentication.
	Header *AuthSource `bson:"header" json:"header"`
	// Username is the username to be used for upstream OAuth2 password authentication.
	Username string `bson:"username" json:"username"`
	// Password is the password to be used for upstream OAuth2 password authentication.
	Password string `bson:"password" json:"password"`
	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string `bson:"tokenUrl" json:"tokenUrl"`
	// Scopes specifies optional requested permissions.
	Scopes []string `bson:"scopes" json:"scopes,omitempty"`
	// ExtraMetadata holds the keys that we want to extract from the token and pass to the upstream.
	ExtraMetadata []string `bson:"extraMetadata" json:"extraMetadata,omitempty"`
}

// ClientAuthData holds the client ID and secret for OAuth2 authentication.
type ClientAuthData struct {
	// ClientID is the application's ID.
	ClientID string `bson:"clientId" json:"clientId"`
	// ClientSecret is the application's secret.
	ClientSecret string `bson:"clientSecret,omitempty" json:"clientSecret,omitempty"` // client secret is optional for password flow
}

// ClientCredentials holds the configuration for OAuth2 Client Credentials flow.
type ClientCredentials struct {
	ClientAuthData
	// Header holds the configuration for the custom header to be used for OAuth authentication.
	Header *AuthSource `bson:"header" json:"header"`
	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string `bson:"tokenUrl" json:"tokenUrl"`
	// Scopes specifies optional requested permissions.
	Scopes []string `bson:"scopes,omitempty" json:"scopes,omitempty"`
	// ExtraMetadata holds the keys that we want to extract from the token and pass to the upstream.
	ExtraMetadata []string `bson:"extraMetadata" json:"extraMetadata,omitempty"`
}

func (c *ClientCredentials) Fill(api apidef.ClientCredentials) {
	c.ClientID = api.ClientID
	c.ClientSecret = api.ClientSecret
	c.TokenURL = api.TokenURL
	c.Scopes = api.Scopes
	c.ExtraMetadata = api.ExtraMetadata

	if c.Header == nil {
		c.Header = &AuthSource{}
	}
	c.Header.Fill(api.Header.Enabled, api.Header.Name)
	if ShouldOmit(c.Header) {
		c.Header = nil
	}
}

func (p *PasswordAuthentication) Fill(api apidef.PasswordAuthentication) {
	p.ClientID = api.ClientID
	p.ClientSecret = api.ClientSecret
	p.Username = api.Username
	p.Password = api.Password
	p.TokenURL = api.TokenURL
	p.Scopes = api.Scopes
	p.ExtraMetadata = api.ExtraMetadata
	if p.Header == nil {
		p.Header = &AuthSource{}
	}
	p.Header.Fill(api.Header.Enabled, api.Header.Name)
	if ShouldOmit(p.Header) {
		p.Header = nil
	}
}

func (u *UpstreamOAuth) Fill(api apidef.UpstreamOAuth) {
	u.Enabled = api.Enabled
	u.AllowedAuthorizeTypes = api.AllowedAuthorizeTypes

	if u.ClientCredentials == nil {
		u.ClientCredentials = &ClientCredentials{}
	}
	u.ClientCredentials.Fill(api.ClientCredentials)
	if ShouldOmit(u.ClientCredentials) {
		u.ClientCredentials = nil
	}

	if u.PasswordAuthentication == nil {
		u.PasswordAuthentication = &PasswordAuthentication{}
	}
	u.PasswordAuthentication.Fill(api.PasswordAuthentication)
	if ShouldOmit(u.PasswordAuthentication) {
		u.PasswordAuthentication = nil
	}
}

func (c *ClientCredentials) ExtractTo(api *apidef.ClientCredentials) {
	api.ClientID = c.ClientID
	api.ClientSecret = c.ClientSecret
	api.TokenURL = c.TokenURL
	api.Scopes = c.Scopes
	api.ExtraMetadata = c.ExtraMetadata

	if c.Header == nil {
		c.Header = &AuthSource{}
		defer func() {
			c.Header = nil
		}()
	}
	c.Header.ExtractTo(&api.Header.Enabled, &api.Header.Name)
}

func (p *PasswordAuthentication) ExtractTo(api *apidef.PasswordAuthentication) {
	api.ClientID = p.ClientID
	api.ClientSecret = p.ClientSecret
	api.Username = p.Username
	api.Password = p.Password
	api.TokenURL = p.TokenURL
	api.Scopes = p.Scopes
	api.ExtraMetadata = p.ExtraMetadata

	if p.Header == nil {
		p.Header = &AuthSource{}
		defer func() {
			p.Header = nil
		}()
	}
	p.Header.ExtractTo(&api.Header.Enabled, &api.Header.Name)
}

func (u *UpstreamOAuth) ExtractTo(api *apidef.UpstreamOAuth) {
	api.Enabled = u.Enabled
	api.AllowedAuthorizeTypes = u.AllowedAuthorizeTypes
	if u.ClientCredentials == nil {
		u.ClientCredentials = &ClientCredentials{}
		defer func() {
			u.ClientCredentials = nil
		}()
	}
	u.ClientCredentials.ExtractTo(&api.ClientCredentials)

	if u.PasswordAuthentication == nil {
		u.PasswordAuthentication = &PasswordAuthentication{}
		defer func() {
			u.PasswordAuthentication = nil
		}()
	}
	u.PasswordAuthentication.ExtractTo(&api.PasswordAuthentication)
}
