package oas

import (
	"crypto/tls"
	"fmt"
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

	// UptimeTests contains the configuration related to uptime tests.
	// Tyk classic API definition: `uptime_tests` and `check_host_against_uptime_tests`.
	UptimeTests *UptimeTests `bson:"uptimeTests,omitempty" json:"uptimeTests,omitempty"`

	// MutualTLS contains the configuration for establishing a mutual TLS connection between Tyk and the upstream server.
	// Tyk classic API definition: `upstream_certificates_disabled` and `upstream_certificates`.
	MutualTLS *MutualTLS `bson:"mutualTLS,omitempty" json:"mutualTLS,omitempty"`

	// CertificatePinning contains the configuration related to certificate pinning.
	// Tyk classic API definition: `certificate_pinning_disabled` and `pinned_public_keys`.
	CertificatePinning *CertificatePinning `bson:"certificatePinning,omitempty" json:"certificatePinning,omitempty"`

	// RateLimit contains the configuration related to API level rate limit.
	// Tyk classic API definition: `global_rate_limit`.
	RateLimit *RateLimit `bson:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Authentication contains the configuration related to upstream authentication.
	// Tyk classic API definition: `upstream_auth`.
	Authentication *UpstreamAuth `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// LoadBalancing contains configuration for load balancing between multiple upstream targets.
	// Tyk classic API definition: `proxy.enable_load_balancing` and `proxy.targets`.
	LoadBalancing *LoadBalancing `bson:"loadBalancing,omitempty" json:"loadBalancing,omitempty"`

	// PreserveHostHeader contains the configuration for preserving the host header.
	// Tyk classic API definition: `proxy.preserve_host_header`.
	PreserveHostHeader *PreserveHostHeader `bson:"preserveHostHeader,omitempty" json:"preserveHostHeader,omitempty"`

	// PreserveTrailingSlash controls whether Tyk preserves trailing slashes in URLs when proxying
	// requests to upstream services. When enabled, URLs like "/users/" will retain the trailing slash.
	// Tyk classic API definition: `proxy.disable_strip_slash`.
	PreserveTrailingSlash *PreserveTrailingSlash `bson:"preserveTrailingSlash,omitempty" json:"preserveTrailingSlash,omitempty"`

	// TLSTransport contains the configuration for TLS transport settings.
	// Tyk classic API definition: `proxy.transport`
	TLSTransport *TLSTransport `bson:"tlsTransport,omitempty" json:"tlsTransport,omitempty"`

	// Proxy contains the configuration for an internal proxy.
	// Tyk classic API definition: `proxy.proxy_url`
	Proxy *Proxy `bson:"proxy,omitempty" json:"proxy,omitempty"`
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

	if u.UptimeTests == nil {
		u.UptimeTests = &UptimeTests{}
	}

	u.UptimeTests.Fill(api.UptimeTests)
	if ShouldOmit(u.UptimeTests) {
		u.UptimeTests = nil
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

	u.Authentication.Fill(api)
	if ShouldOmit(u.Authentication) {
		u.Authentication = nil
	}

	if u.TLSTransport == nil {
		u.TLSTransport = &TLSTransport{}
	}
	u.TLSTransport.Fill(api)
	if ShouldOmit(u.TLSTransport) {
		u.TLSTransport = nil
	}

	if u.Proxy == nil {
		u.Proxy = &Proxy{}
	}
	u.Proxy.Fill(api)
	if ShouldOmit(u.Proxy) {
		u.Proxy = nil
	}

	u.fillLoadBalancing(api)
	u.fillPreserveHostHeader(api)
	u.fillPreserveTrailingSlash(api)
}

func (u *Upstream) fillPreserveTrailingSlash(api apidef.APIDefinition) {
	if u.PreserveTrailingSlash == nil {
		u.PreserveTrailingSlash = &PreserveTrailingSlash{}
	}
	u.PreserveTrailingSlash.Fill(api)

	if !u.PreserveTrailingSlash.Enabled {
		u.PreserveTrailingSlash = nil
	}
}

func (u *Upstream) fillPreserveHostHeader(api apidef.APIDefinition) {
	if u.PreserveHostHeader == nil {
		u.PreserveHostHeader = &PreserveHostHeader{}
	}

	u.PreserveHostHeader.Fill(api)

	if !u.PreserveHostHeader.Enabled {
		u.PreserveHostHeader = nil
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

	if u.UptimeTests == nil {
		u.UptimeTests = &UptimeTests{}
		defer func() {
			u.UptimeTests = nil
		}()
	}

	u.UptimeTests.ExtractTo(&api.UptimeTests)

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

	u.Authentication.ExtractTo(api)

	u.loadBalancingExtractTo(api)

	if u.TLSTransport == nil {
		u.TLSTransport = &TLSTransport{}
		defer func() {
			u.TLSTransport = nil
		}()
	}
	u.TLSTransport.ExtractTo(api)

	if u.Proxy == nil {
		u.Proxy = &Proxy{}
		defer func() {
			u.Proxy = nil
		}()
	}
	u.Proxy.ExtractTo(api)

	u.preserveHostHeaderExtractTo(api)
	u.preserveTrailingSlashExtractTo(api)
}

func (u *Upstream) preserveHostHeaderExtractTo(api *apidef.APIDefinition) {
	if u.PreserveHostHeader == nil {
		u.PreserveHostHeader = &PreserveHostHeader{}
		defer func() {
			u.PreserveHostHeader = nil
		}()
	}

	u.PreserveHostHeader.ExtractTo(api)
}

func (u *Upstream) preserveTrailingSlashExtractTo(api *apidef.APIDefinition) {
	if u.PreserveTrailingSlash == nil {
		u.PreserveTrailingSlash = &PreserveTrailingSlash{}
		defer func() {
			u.PreserveTrailingSlash = nil
		}()
	}

	u.PreserveTrailingSlash.ExtractTo(api)
}

func (u *Upstream) fillLoadBalancing(api apidef.APIDefinition) {
	if u.LoadBalancing == nil {
		u.LoadBalancing = &LoadBalancing{}
	}

	u.LoadBalancing.Fill(api)
	if ShouldOmit(u.LoadBalancing) {
		u.LoadBalancing = nil
	}
}

func (u *Upstream) loadBalancingExtractTo(api *apidef.APIDefinition) {
	if u.LoadBalancing == nil {
		u.LoadBalancing = &LoadBalancing{}
		defer func() {
			u.LoadBalancing = nil
		}()
	}

	u.LoadBalancing.ExtractTo(api)
}

// TLSTransport contains the configuration for TLS transport settings.
// This struct allows you to specify a custom proxy and set the minimum TLS versions and any SSL ciphers.
//
// Example:
//
//	```
//	{
//	  "proxy_url": "http(s)://proxy.url:1234",
//	  "minVersion": "1.0",
//	  "maxVersion": "1.0",
//	  "ciphers": [
//	    "TLS_RSA_WITH_AES_128_GCM_SHA256",
//	    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
//	  ],
//	  "insecureSkipVerify": true,
//	  "forceCommonNameCheck": false
//	}
//	```
//
// Tyk classic API definition: `proxy.transport`
type TLSTransport struct {
	// InsecureSkipVerify controls whether a client verifies the server's certificate chain and host name.
	// If InsecureSkipVerify is true, crypto/tls accepts any certificate presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used.
	// This should be used only for testing or in combination with VerifyConnection or VerifyPeerCertificate.
	//
	// Tyk classic API definition: `proxy.transport.ssl_insecure_skip_verify`
	InsecureSkipVerify bool `bson:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// Ciphers is a list of SSL ciphers to be used. If unset, the default ciphers will be used.
	//
	// Tyk classic API definition: `proxy.transport.ssl_ciphers`
	Ciphers []string `bson:"ciphers,omitempty" json:"ciphers,omitempty"`

	// MinVersion is the minimum SSL/TLS version that is acceptable.
	// Tyk classic API definition: `proxy.transport.ssl_min_version`
	MinVersion string `bson:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum SSL/TLS version that is acceptable.
	MaxVersion string `bson:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// ForceCommonNameCheck forces the validation of the hostname against the certificate Common Name.
	//
	// Tyk classic API definition: `proxy.transport.ssl_force_common_name_check`
	ForceCommonNameCheck bool `bson:"forceCommonNameCheck,omitempty" json:"forceCommonNameCheck,omitempty"`
}

// Fill fills *TLSTransport from apidef.ServiceDiscoveryConfiguration.
func (t *TLSTransport) Fill(api apidef.APIDefinition) {
	t.ForceCommonNameCheck = api.Proxy.Transport.SSLForceCommonNameCheck
	t.Ciphers = api.Proxy.Transport.SSLCipherSuites
	t.MaxVersion = t.tlsVersionToString(api.Proxy.Transport.SSLMaxVersion)
	t.MinVersion = t.tlsVersionToString(api.Proxy.Transport.SSLMinVersion)
	t.InsecureSkipVerify = api.Proxy.Transport.SSLInsecureSkipVerify
}

// ExtractTo extracts *TLSTransport into *apidef.ServiceDiscoveryConfiguration.
func (t *TLSTransport) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.Transport.SSLForceCommonNameCheck = t.ForceCommonNameCheck
	api.Proxy.Transport.SSLCipherSuites = t.Ciphers
	api.Proxy.Transport.SSLMaxVersion = t.tlsVersionFromString(t.MaxVersion)
	api.Proxy.Transport.SSLMinVersion = t.tlsVersionFromString(t.MinVersion)
	api.Proxy.Transport.SSLInsecureSkipVerify = t.InsecureSkipVerify
}

// tlsVersionFromString converts v in the form of 1.2/1.3 to the version int
func (t *TLSTransport) tlsVersionFromString(v string) uint16 {
	switch v {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// tlsVersionFromString converts v from version into to the form 1.0/1.1
func (t *TLSTransport) tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return ""
	}
}

// Proxy contains the configuration for an internal proxy.
//
// Tyk classic API definition: `proxy.proxy_url`
type Proxy struct {
	// Enabled determines if the proxy is active.
	Enabled bool `bson:"enabled" json:"enabled"`

	// URL specifies the URL of the internal proxy.
	URL string `bson:"url" json:"url"`
}

// Fill fills *Proxy from apidef.ServiceDiscoveryConfiguration.
func (p *Proxy) Fill(api apidef.APIDefinition) {
	p.URL = api.Proxy.Transport.ProxyURL
}

// ExtractTo extracts *Proxy into *apidef.ServiceDiscoveryConfiguration.
func (p *Proxy) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.Transport.ProxyURL = p.URL
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

	timeout, enabled := serviceDiscovery.CacheOptions()
	sd.Cache = &ServiceDiscoveryCache{
		Enabled: enabled && sd.Enabled,
		Timeout: timeout,
	}

	if !sd.Cache.Enabled {
		sd.Cache = nil
	}

	sd.CacheTimeout = 0
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
	serviceDiscovery.CacheDisabled = !enabled
	serviceDiscovery.CacheTimeout = timeout
	if !sd.Enabled {
		serviceDiscovery.CacheDisabled = true
	}
}

// UptimeTests configures uptime tests.
type UptimeTests struct {
	// Enabled specifies whether the uptime tests are active or not.
	// Tyk classic API definition: `uptime_tests.disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// ServiceDiscovery contains the configuration related to test Service Discovery.
	// Tyk classic API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`

	// Tests contains individual connectivity tests defined for checking if a service is online.
	Tests []UptimeTest `bson:"tests,omitempty" json:"tests,omitempty"`

	// HostDownRetestPeriod is the time to wait until rechecking a failed test.
	// If undefined, the default testing interval (10s) is in use.
	// Setting this to a lower value would result in quicker recovery on failed checks.
	HostDownRetestPeriod time.ReadableDuration `bson:"hostDownRetestPeriod" json:"hostDownRetestPeriod,omitempty"`

	// LogRetentionPeriod holds a time to live for the uptime test results.
	// If unset, a value of 100 years is the default.
	LogRetentionPeriod time.ReadableDuration `bson:"logRetentionPeriod" json:"logRetentionPeriod,omitempty"`
}

// UptimeTest configures an uptime test check.
type UptimeTest struct {
	// CheckURL is the URL for a request. If service discovery is in use,
	// the hostname will be resolved to a service host.
	//
	// Examples:
	//
	// - `http://database1.company.local`
	// - `https://webcluster.service/health`
	// - `tcp://127.0.0.1:6379` (for TCP checks).
	CheckURL string `bson:"url" json:"url"`

	// Timeout declares a timeout for the request. If the test exceeds
	// this timeout, the check fails.
	Timeout time.ReadableDuration `bson:"timeout" json:"timeout,omitempty"`

	// Method allows you to customize the HTTP method for the test (`GET`, `POST`,...).
	Method string `bson:"method" json:"method"`

	// Headers contain any custom headers for the back end service.
	Headers map[string]string `bson:"headers" json:"headers,omitempty"`

	// Body is the body of the test request.
	Body string `bson:"body" json:"body,omitempty"`

	// Commands are used for TCP checks.
	Commands []UptimeTestCommand `bson:"commands" json:"commands,omitempty"`

	// EnableProxyProtocol enables proxy protocol support when making request.
	// The back end service needs to support this.
	EnableProxyProtocol bool `bson:"enableProxyProtocol" json:"enableProxyProtocol"`
}

// AddCommand will append a new command to the test.
func (t *UptimeTest) AddCommand(name, message string) {
	command := UptimeTestCommand{
		Name:    name,
		Message: message,
	}

	t.Commands = append(t.Commands, command)
}

// UptimeTestCommand handles additional checks for tcp connections.
type UptimeTestCommand struct {
	// Name can be either `send` or `expect`, designating if the
	// message should be sent, or read from the connection.
	Name string `bson:"name" json:"name"`

	// Message contains the payload to send or expect.
	Message string `bson:"message" json:"message"`
}

// Fill fills *UptimeTests from apidef.UptimeTests.
func (u *UptimeTests) Fill(uptimeTests apidef.UptimeTests) {
	if u.ServiceDiscovery == nil {
		u.ServiceDiscovery = &ServiceDiscovery{}
	}

	u.ServiceDiscovery.Fill(uptimeTests.Config.ServiceDiscovery)

	if ShouldOmit(u.ServiceDiscovery) {
		u.ServiceDiscovery = nil
	}

	u.LogRetentionPeriod = ReadableDuration(time.Duration(uptimeTests.Config.ExpireUptimeAnalyticsAfter) * time.Second)
	u.HostDownRetestPeriod = ReadableDuration(time.Duration(uptimeTests.Config.RecheckWait) * time.Second)

	u.Tests = nil
	for _, v := range uptimeTests.CheckList {
		check := UptimeTest{
			CheckURL:            u.fillCheckURL(v.Protocol, v.CheckURL),
			Timeout:             ReadableDuration(v.Timeout),
			Method:              v.Method,
			Headers:             v.Headers,
			Body:                v.Body,
			EnableProxyProtocol: v.EnableProxyProtocol,
		}
		for _, command := range v.Commands {
			check.AddCommand(command.Name, command.Message)
		}
		u.Tests = append(u.Tests, check)
	}

	u.Enabled = len(u.Tests) > 0 && !uptimeTests.Disabled
}

// ExtractTo extracts *UptimeTests into *apidef.UptimeTests.
func (u *UptimeTests) ExtractTo(uptimeTests *apidef.UptimeTests) {
	uptimeTests.Disabled = !u.Enabled

	if u.ServiceDiscovery == nil {
		u.ServiceDiscovery = &ServiceDiscovery{}
		defer func() {
			u.ServiceDiscovery = nil
		}()
	}

	u.ServiceDiscovery.ExtractTo(&uptimeTests.Config.ServiceDiscovery)

	uptimeTests.Config.ExpireUptimeAnalyticsAfter = int64(u.LogRetentionPeriod.Seconds())
	uptimeTests.Config.RecheckWait = int(u.HostDownRetestPeriod.Seconds())

	uptimeTests.CheckList = nil

	result := []apidef.HostCheckObject{}
	for _, v := range u.Tests {
		classicProtocol, classicCheckURL := u.extractToProtocolAndCheckURL(v.CheckURL)
		check := apidef.HostCheckObject{
			CheckURL:            classicCheckURL,
			Protocol:            classicProtocol,
			Timeout:             time.Duration(v.Timeout),
			Method:              v.Method,
			Headers:             v.Headers,
			Body:                v.Body,
			EnableProxyProtocol: v.EnableProxyProtocol,
		}
		for _, command := range v.Commands {
			check.AddCommand(command.Name, command.Message)
		}

		result = append(result, check)
	}

	if len(result) > 0 {
		uptimeTests.CheckList = result
	}
}

// fillCheckURL constructs a valid URL by appending the protocol to the provided URL, removing any existing protocol.
// This needs to be done because classic can have invalid protocol and checkURL combinations, e.g.
// protocol=tcp, checkURL=https://myservice.fake
func (u *UptimeTests) fillCheckURL(protocol string, checkURL string) string {
	// in classic API, protocol can be empty so we need to check for that and return the original URL
	if protocol == "" {
		return checkURL
	}
	protocolessURL := checkURL
	splitURL := strings.Split(checkURL, "://")
	if len(splitURL) > 1 {
		protocolessURL = splitURL[1]
	}

	return fmt.Sprintf("%s://%s", protocol, protocolessURL)
}

// extractToProtocolAndCheckURL splits a URL into its protocol and the remaining part of the URL, returning both as strings.
// Classic has a special field for protocol while OAS only has checkURL. The protocol should remain inside checkURL.
func (u *UptimeTests) extractToProtocolAndCheckURL(checkURL string) (classicProtocol, classicCheckURL string) {
	splitURL := strings.Split(checkURL, "://")
	if len(splitURL) > 1 {
		return splitURL[0], checkURL
	}
	return "", checkURL // should never happen, but let's be sure to not have panics
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
	// RequestSigning holds the configuration for generating signed requests to an upstream API.
	RequestSigning *UpstreamRequestSigning `bson:"requestSigning,omitempty" json:"requestSigning,omitempty"`
}

// Fill fills *UpstreamAuth from apidef.APIDefinition.
func (u *UpstreamAuth) Fill(api apidef.APIDefinition) {
	u.Enabled = api.UpstreamAuth.Enabled

	if u.BasicAuth == nil {
		u.BasicAuth = &UpstreamBasicAuth{}
	}
	u.BasicAuth.Fill(api.UpstreamAuth.BasicAuth)
	if ShouldOmit(u.BasicAuth) {
		u.BasicAuth = nil
	}

	if u.OAuth == nil {
		u.OAuth = &UpstreamOAuth{}
	}
	u.OAuth.Fill(api.UpstreamAuth.OAuth)
	if ShouldOmit(u.OAuth) {
		u.OAuth = nil
	}

	u.fillRequestSigning(api)
}

// ExtractTo extracts *UpstreamAuth into *apidef.APIDefinition.
func (u *UpstreamAuth) ExtractTo(api *apidef.APIDefinition) {
	api.UpstreamAuth.Enabled = u.Enabled

	if u.BasicAuth == nil {
		u.BasicAuth = &UpstreamBasicAuth{}
		defer func() {
			u.BasicAuth = nil
		}()
	}
	u.BasicAuth.ExtractTo(&api.UpstreamAuth.BasicAuth)

	if u.OAuth == nil {
		u.OAuth = &UpstreamOAuth{}
		defer func() {
			u.OAuth = nil
		}()
	}
	u.OAuth.ExtractTo(&api.UpstreamAuth.OAuth)

	u.requestSigningExtractTo(api)
}

func (u *UpstreamAuth) fillRequestSigning(api apidef.APIDefinition) {
	if u.RequestSigning == nil {
		u.RequestSigning = &UpstreamRequestSigning{}
	}
	u.RequestSigning.Fill(api)
	if ShouldOmit(u.RequestSigning) {
		u.RequestSigning = nil
	}
}

func (u *UpstreamAuth) requestSigningExtractTo(api *apidef.APIDefinition) {
	if u.RequestSigning == nil {
		u.RequestSigning = &UpstreamRequestSigning{}
		defer func() {
			u.BasicAuth = nil
		}()
	}
	u.RequestSigning.ExtractTo(api)
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

// UpstreamRequestSigning represents configuration for generating signed requests to an upstream API.
// Tyk classic API definition: `request_signing`.
type UpstreamRequestSigning struct {
	// Enabled determines if request signing is enabled or disabled.
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// SignatureHeader specifies the HTTP header name for the signature.
	SignatureHeader string `bson:"signatureHeader,omitempty" json:"signatureHeader,omitempty"`
	// Algorithm represents the signing algorithm used (e.g., HMAC-SHA256).
	Algorithm string `bson:"algorithm,omitempty" json:"algorithm,omitempty"`
	// KeyID identifies the key used for signing purposes.
	KeyID string `bson:"keyId,omitempty" json:"keyId,omitempty"`
	// Headers contains a list of headers included in the signature calculation.
	Headers []string `bson:"headers,omitempty" json:"headers,omitempty"`
	// Secret holds the secret used for signing when applicable.
	Secret string `bson:"secret,omitempty" json:"secret,omitempty"`
	// CertificateID specifies the certificate ID used in signing operations.
	CertificateID string `bson:"certificateId,omitempty" json:"certificateId,omitempty"`
}

// Fill populates the UpstreamRequestSigning fields from the given apidef.APIDefinition configuration.
func (l *UpstreamRequestSigning) Fill(api apidef.APIDefinition) {
	l.Enabled = api.RequestSigning.IsEnabled
	l.SignatureHeader = api.RequestSigning.SignatureHeader
	l.Algorithm = api.RequestSigning.Algorithm
	l.KeyID = api.RequestSigning.KeyId
	l.Headers = api.RequestSigning.HeaderList
	l.Secret = api.RequestSigning.Secret
	l.CertificateID = api.RequestSigning.CertificateId
}

// ExtractTo populates the given apidef.APIDefinition RequestSigning fields with values from the UpstreamRequestSigning.
func (l *UpstreamRequestSigning) ExtractTo(api *apidef.APIDefinition) {
	api.RequestSigning.IsEnabled = l.Enabled
	api.RequestSigning.SignatureHeader = l.SignatureHeader
	api.RequestSigning.Algorithm = l.Algorithm
	api.RequestSigning.KeyId = l.KeyID
	api.RequestSigning.HeaderList = l.Headers
	api.RequestSigning.Secret = l.Secret
	api.RequestSigning.CertificateId = l.CertificateID
}

// LoadBalancing represents the configuration for load balancing between multiple upstream targets.
type LoadBalancing struct {
	// Enabled determines if load balancing is active.
	Enabled bool `json:"enabled" bson:"enabled"` // required
	// SkipUnavailableHosts determines whether to skip unavailable hosts during load balancing based on uptime tests.
	// Tyk classic field: `proxy.check_host_against_uptime_tests`
	SkipUnavailableHosts bool `json:"skipUnavailableHosts,omitempty" bson:"skipUnavailableHosts,omitempty"`
	// Targets defines the list of targets with their respective weights for load balancing.
	Targets []LoadBalancingTarget `json:"targets,omitempty" bson:"targets,omitempty"`
}

// LoadBalancingTarget represents a single upstream target for load balancing with a URL and an associated weight.
type LoadBalancingTarget struct {
	// URL specifies the upstream target URL for load balancing, represented as a string.
	URL string `json:"url" bson:"url"` // required
	// Weight specifies the relative distribution factor for load balancing, determining the importance of this target.
	Weight int `json:"weight" bson:"weight"` // required
}

// Fill populates the LoadBalancing structure based on the provided APIDefinition, including targets and their weights.
func (l *LoadBalancing) Fill(api apidef.APIDefinition) {
	if len(api.Proxy.Targets) == 0 {
		api.Proxy.EnableLoadBalancing = false
		api.Proxy.CheckHostAgainstUptimeTests = false
		api.Proxy.Targets = nil
		return
	}

	l.Enabled = api.Proxy.EnableLoadBalancing
	l.SkipUnavailableHosts = api.Proxy.CheckHostAgainstUptimeTests

	targetCounter := make(map[string]*LoadBalancingTarget)
	for _, target := range api.Proxy.Targets {
		if _, ok := targetCounter[target]; !ok {
			targetCounter[target] = &LoadBalancingTarget{
				URL:    target,
				Weight: 0,
			}
		}
		targetCounter[target].Weight++
	}

	targets := make([]LoadBalancingTarget, len(targetCounter))
	i := 0
	for _, target := range targetCounter {
		targets[i] = *target
		i++
	}

	targetsSorter := func(i, j int) bool {
		return targets[i].URL < targets[j].URL
	}

	sort.Slice(targets, targetsSorter)
	l.Targets = targets
}

// ExtractTo populates an APIDefinition's proxy load balancing configuration with data from the LoadBalancing instance.
func (l *LoadBalancing) ExtractTo(api *apidef.APIDefinition) {
	if len(l.Targets) == 0 {
		api.Proxy.EnableLoadBalancing = false
		api.Proxy.CheckHostAgainstUptimeTests = false
		api.Proxy.Targets = nil
		return
	}

	proxyConfTargets := make([]string, 0, len(l.Targets))
	api.Proxy.EnableLoadBalancing = l.Enabled
	api.Proxy.CheckHostAgainstUptimeTests = l.SkipUnavailableHosts
	for _, target := range l.Targets {
		for i := 0; i < target.Weight; i++ {
			proxyConfTargets = append(proxyConfTargets, target.URL)
		}
	}

	api.Proxy.Targets = proxyConfTargets
}

// PreserveHostHeader holds the configuration for preserving the host header.
type PreserveHostHeader struct {
	// Enabled activates preserving the host header.
	Enabled bool `json:"enabled" bson:"enabled"`
}

// Fill fills *PreserveHostHeader from apidef.APIDefinition.
func (p *PreserveHostHeader) Fill(api apidef.APIDefinition) {
	p.Enabled = api.Proxy.PreserveHostHeader
}

// ExtractTo extracts *PreserveHostHeader into *apidef.APIDefinition.
func (p *PreserveHostHeader) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.PreserveHostHeader = p.Enabled
}

// PreserveTrailingSlash holds the configuration for preserving the
// trailing slash when routed to upstream services.
//
// The default behaviour of Tyk is to strip any trailing slash (/) from
// the target URL when proxying the request upstream. In some use cases the
// upstream might expect the trailing slash - or might consider /users/ to
// be a different endpoint from /users (for example).
type PreserveTrailingSlash struct {
	// Enabled activates preserving the trailing slash when routing requests.
	Enabled bool `json:"enabled" bson:"enabled"` // required
}

// Fill fills *PreserveTrailingSlash from apidef.APIDefinition.
func (p *PreserveTrailingSlash) Fill(api apidef.APIDefinition) {
	p.Enabled = api.Proxy.DisableStripSlash
}

// ExtractTo extracts *PreserveTrailingSlash into *apidef.APIDefinition.
func (p *PreserveTrailingSlash) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.DisableStripSlash = p.Enabled
}
