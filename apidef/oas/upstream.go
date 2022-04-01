package oas

import "github.com/TykTechnologies/tyk/apidef"

type Upstream struct {
	// URL defines the target URL that the request should be proxied to.
	// Old API Definition: `proxy.target_url`
	URL string `bson:"url" json:"url"` // required
	// ServiceDiscovery contains the configuration related to Service Discovery.
	// Old API Definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`
	// Test contains the configuration related to uptime tests.
	Test             *Test            `bson:"test,omitempty" json:"test,omitempty"`
	Certificates     Certificates     `bson:"certificates,omitempty" json:"certificates,omitempty"`
	PinnedPublicKeys PinnedPublicKeys `bson:"pinnedPublicKeys,omitempty" json:"PinnedPublicKeys,omitempty"`
}

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

	u.Certificates = make(Certificates, len(api.UpstreamCertificates))
	u.Certificates.Fill(api.UpstreamCertificates)

	if len(u.Certificates) == 0 {
		u.Certificates = nil
	}

	u.PinnedPublicKeys = make(PinnedPublicKeys, len(api.PinnedPublicKeys))
	u.PinnedPublicKeys.Fill(api.PinnedPublicKeys)

	if len(u.PinnedPublicKeys) == 0 {
		u.PinnedPublicKeys = nil
	}
}

func (u *Upstream) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.TargetURL = u.URL

	if u.ServiceDiscovery != nil {
		u.ServiceDiscovery.ExtractTo(&api.Proxy.ServiceDiscovery)
	}

	if u.Test != nil {
		u.Test.ExtractTo(&api.UptimeTests)
	}

	if len(api.UpstreamCertificates) > 0 {
		u.Certificates.ExtractTo(api.UpstreamCertificates)
	}

	if len(api.PinnedPublicKeys) > 0 {
		u.PinnedPublicKeys.ExtractTo(api.PinnedPublicKeys)
	}
}

type ServiceDiscovery struct {
	// Enabled enables Service Discovery.
	// Old API Definition: `service_discovery.use_discovery_service`
	Enabled bool `bson:"enabled" json:"enabled"` // required
	// QueryEndpoint is the endpoint to call, this would usually be Consul, etcd or Eureka K/V store.
	// Old API Definition: `service_discovery.query_endpoint`
	QueryEndpoint string `bson:"queryEndpoint,omitempty" json:"queryEndpoint,omitempty"`
	// DataPath is the namespace of the data path - where exactly in your service response the namespace can be found.
	// For example, if your service responds with:
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
	//```
	//
	// then your namespace would be `node.value`.
	// Old API Definition: `service_discovery.data_path`
	DataPath string `bson:"dataPath,omitempty" json:"dataPath,omitempty"`
	// UseNestedQuery enables using a combination of `dataPath` and `parentDataPath`.
	// It is necessary when the data lives within this string-encoded JSON object.
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
	//```
	// Old API Definition: `service_discovery.use_nested_query`
	UseNestedQuery bool `bson:"useNestedQuery,omitempty" json:"useNestedQuery,omitempty"`
	// ParentDataPath is the namespace of the where to find the nested value, if `useNestedQuery` is `true`.
	// In the above example, it would be `node.value`. You would then change the `dataPath` setting to be `hostname`,
	// since this is where the host name data resides in the JSON string.
	// Tyk automatically assumes that `dataPath` in this case is in a string-encoded JSON object and will try to deserialize it.
	// Old API Definition: `service_discovery.parent_data_path`
	ParentDataPath string `bson:"parentDataPath,omitempty" json:"parentDataPath,omitempty"`
	// PortDataPath is the port of the data path. In the above nested example, we can see that there is a separate `port` value
	// for the service in the nested JSON. In this case, you can set the `portDataPath` value and Tyk will treat `dataPath`
	// as the hostname and zip them together (this assumes that the hostname element does not end in a slash or resource identifier
	// such as `/widgets/`). In the above example, the `portDataPath` would be `port`.
	// Old API Definition: `service_discovery.port_data_path`
	PortDataPath string `bson:"portDataPath,omitempty" json:"portDataPath,omitempty"`
	// UseTargetList should be set to `true`, if you are using load balancing. Tyk will treat the data path as a list and
	// inject it into the target list of your API Definition.
	// Old API Definition: `service_discovery.use_target_list`
	UseTargetList bool `bson:"useTargetList,omitempty" json:"useTargetList,omitempty"`
	// CacheTimeout is the timeout of a cache value when a new data is loaded from a discovery service.
	// Setting it too low will cause Tyk to call the SD service too often, setting it too high could mean that
	// failures are not recovered from quickly enough.
	// Old API Definition: `service_discovery.cache_timeout`
	CacheTimeout int64 `bson:"cacheTimeout,omitempty" json:"cacheTimeout,omitempty"`
	// TargetPath is to set a target path to append to the discovered endpoint, since many SD services
	// only provide host and port data. It is important to be able to target a specific resource on that host.
	// Setting this value will enable that.
	// Old API Definition: `service_discovery.target_path`
	TargetPath string `bson:"targetPath,omitempty" json:"targetPath,omitempty"`
	// EndpointReturnsList is set `true` when the response type is a list instead of an object.
	// Old API Definition: `service_discovery.endpoint_returns_list`
	EndpointReturnsList bool `bson:"endpointReturnsList,omitempty" json:"endpointReturnsList,omitempty"`
}

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

type Test struct {
	// ServiceDiscovery contains the configuration related to test Service Discovery.
	// Old API Definition: `proxy.service_discovery`
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`
}

func (t *Test) Fill(uptimeTests apidef.UptimeTests) {
	if t.ServiceDiscovery == nil {
		t.ServiceDiscovery = &ServiceDiscovery{}
	}

	t.ServiceDiscovery.Fill(uptimeTests.Config.ServiceDiscovery)
	if ShouldOmit(t.ServiceDiscovery) {
		t.ServiceDiscovery = nil
	}
}

func (t *Test) ExtractTo(uptimeTests *apidef.UptimeTests) {
	if t.ServiceDiscovery != nil {
		t.ServiceDiscovery.ExtractTo(&uptimeTests.Config.ServiceDiscovery)
	}
}
