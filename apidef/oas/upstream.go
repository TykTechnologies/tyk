package oas

import (
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// Upstream holds configuration for an upstream server.
type Upstream struct {
	// URL defines the target URL that the request should be proxied to.
	// Tyk native API definition: `proxy.target_url`
	URL string `bson:"url" json:"url"` // required

	// ServiceDiscovery contains the configuration related to Service Discovery.
	// Tyk native API definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`

	// Test contains the configuration related to uptime tests.
	Test *Test `bson:"test,omitempty" json:"test,omitempty"`

	// MutualTLS contains the configuration related to upstream mutual TLS.
	MutualTLS *MutualTLS `bson:"mutualTLS,omitempty" json:"mutualTLS,omitempty"`

	// CertificatePinning contains the configuration related to certificate pinning.
	CertificatePinning *CertificatePinning `bson:"certificatePinning,omitempty" json:"certificatePinning,omitempty"`
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
}

// ExtractTo extracts *Upstream into *apidef.APIDefinition.
func (u *Upstream) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.TargetURL = u.URL

	if u.ServiceDiscovery != nil {
		u.ServiceDiscovery.ExtractTo(&api.Proxy.ServiceDiscovery)
	}

	if u.Test != nil {
		u.Test.ExtractTo(&api.UptimeTests)
	}

	if u.MutualTLS != nil {
		u.MutualTLS.ExtractTo(api)
	} else {
		api.UpstreamCertificatesDisabled = true
		api.UpstreamCertificates = nil
	}

	if u.CertificatePinning != nil {
		u.CertificatePinning.ExtractTo(api)
	} else {
		api.CertificatePinningDisabled = true
		api.PinnedPublicKeys = nil
	}
}

// ServiceDiscovery holds configuration required for service discovery.
type ServiceDiscovery struct {
	// Enabled enables Service Discovery.
	//
	// Tyk native API definition: `service_discovery.use_discovery_service`
	Enabled bool `bson:"enabled" json:"enabled"` // required

	// QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.
	// Tyk native API definition: `service_discovery.query_endpoint`
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
	// Tyk native API definition: `service_discovery.data_path`
	DataPath string `bson:"dataPath,omitempty" json:"dataPath,omitempty"`

	// UseNestedQuery enables using a combination of `dataPath` and `parentDataPath`.
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
	// Tyk native API definition: `service_discovery.use_nested_query`
	UseNestedQuery bool `bson:"useNestedQuery,omitempty" json:"useNestedQuery,omitempty"`

	// ParentDataPath is the namespace of the where to find the nested
	// value, if `useNestedQuery` is `true`. In the above example, it
	// would be `node.value`. You would change the `dataPath` setting
	// to be `hostname`, since this is where the host name data
	// resides in the JSON string. Tyk automatically assumes that
	// `dataPath` in this case is in a string-encoded JSON object and
	// will try to deserialize it.
	//
	// Tyk native API definition: `service_discovery.parent_data_path`
	ParentDataPath string `bson:"parentDataPath,omitempty" json:"parentDataPath,omitempty"`

	// PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value
	// for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath` as
	// the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier
	// such as `/widgets/`). In the above example, the `portDataPath` would be `port`.
	//
	// Tyk native API definition: `service_discovery.port_data_path`
	PortDataPath string `bson:"portDataPath,omitempty" json:"portDataPath,omitempty"`

	// UseTargetList should be set to `true`, if you are using load balancing. Tyk will treat the data path as a list and
	// inject it into the target list of your API definition.
	//
	// Tyk native API definition: `service_discovery.use_target_list`
	UseTargetList bool `bson:"useTargetList,omitempty" json:"useTargetList,omitempty"`

	// CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
	// Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that
	// failures are not recovered from quickly enough.
	//
	// Tyk native API definition: `service_discovery.cache_timeout`
	CacheTimeout int64 `bson:"cacheTimeout,omitempty" json:"cacheTimeout,omitempty"`

	// TargetPath is to set a target path to append to the discovered endpoint, since many SD services
	// only provide host and port data. It is important to be able to target a specific resource on that host.
	// Setting this value will enable that.
	//
	// Tyk native API definition: `service_discovery.target_path`
	TargetPath string `bson:"targetPath,omitempty" json:"targetPath,omitempty"`

	// EndpointReturnsList is set `true` when the response type is a list instead of an object.
	//
	// Tyk native API definition: `service_discovery.endpoint_returns_list`
	EndpointReturnsList bool `bson:"endpointReturnsList,omitempty" json:"endpointReturnsList,omitempty"`
}

// Fill fills *ServiceDiscovery from apidef.ServiceDiscoveryConfiguration.
func (sd *ServiceDiscovery) Fill(serviceDiscovery apidef.ServiceDiscoveryConfiguration) {
	sd.Enabled = serviceDiscovery.UseDiscoveryService
	sd.EndpointReturnsList = serviceDiscovery.EndpointReturnsList
	sd.CacheTimeout = serviceDiscovery.CacheTimeout
	sd.ParentDataPath = serviceDiscovery.ParentDataPath
	sd.QueryEndpoint = serviceDiscovery.QueryEndpoint
	sd.TargetPath = serviceDiscovery.TargetPath
	sd.UseTargetList = serviceDiscovery.UseTargetList
	sd.UseNestedQuery = serviceDiscovery.UseNestedQuery
	sd.DataPath = serviceDiscovery.DataPath
	sd.PortDataPath = serviceDiscovery.PortDataPath
}

// ExtractTo extracts *ServiceDiscovery into *apidef.ServiceDiscoveryConfiguration.
func (sd *ServiceDiscovery) ExtractTo(serviceDiscovery *apidef.ServiceDiscoveryConfiguration) {
	serviceDiscovery.UseDiscoveryService = sd.Enabled
	serviceDiscovery.EndpointReturnsList = sd.EndpointReturnsList
	serviceDiscovery.CacheTimeout = sd.CacheTimeout
	serviceDiscovery.ParentDataPath = sd.ParentDataPath
	serviceDiscovery.QueryEndpoint = sd.QueryEndpoint
	serviceDiscovery.TargetPath = sd.TargetPath
	serviceDiscovery.UseTargetList = sd.UseTargetList
	serviceDiscovery.UseNestedQuery = sd.UseNestedQuery
	serviceDiscovery.DataPath = sd.DataPath
	serviceDiscovery.PortDataPath = sd.PortDataPath
}

// Test holds the test configuration for service discovery.
type Test struct {
	// ServiceDiscovery contains the configuration related to test Service Discovery.
	// Tyk native API definition: `proxy.service_discovery`
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
	if t.ServiceDiscovery != nil {
		t.ServiceDiscovery.ExtractTo(&uptimeTests.Config.ServiceDiscovery)
	}
}

// MutualTLS holds configuration related to mTLS on APIs, domain to certificate mappings.
type MutualTLS struct {
	// Enabled enables/disables upstream mutual TLS auth for the API.
	// Tyk native API definition: `upstream_certificates_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToCertificates maintains the mapping of domain to certificate.
	// Tyk native API definition: `upstream_certificates`
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
}

// ExtractTo extracts *MutualTLS into *apidef.APIDefinition.
func (m *MutualTLS) ExtractTo(api *apidef.APIDefinition) {
	api.UpstreamCertificatesDisabled = !m.Enabled

	if len(m.DomainToCertificates) > 0 {
		api.UpstreamCertificates = make(map[string]string)
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
	// Tyk native API definition: `certificate_pinning_disabled`
	Enabled bool `bson:"enabled" json:"enabled"`

	// DomainToPublicKeysMapping maintains the mapping of domain to pinned public keys.
	//
	// Tyk native API definition: `pinned_public_keys`
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
	}
}
