# Uptime tests

```
UptimeTests{
	"check_list": []HostCheckObject{
		CheckURL            string            `json:"url"`
		Protocol            string            `json:"protocol"`
		Timeout             time.Duration     `json:"timeout"`
		EnableProxyProtocol bool              `json:"enable_proxy_protocol"`
		Commands            []CheckCommand    `json:"commands"`
		Method              string            `json:"method"`
		Headers             map[string]string `json:"headers"`
		Body                string            `json:"body"`
	},
	"config": UptimeTestsConfig{
		"expire_utime_after": int64,
		"service_discovery": ServiceDiscoveryConfiguration{
			UseDiscoveryService	bool	`json:"use_discovery_service"`
			QueryEndpoint		string	`json:"query_endpoint"`
			UseNestedQuery		bool	`json:"use_nested_query"`
			ParentDataPath		string	`json:"parent_data_path"`
			DataPath		string	`json:"data_path"`
			PortDataPath		string	`json:"port_data_path"`
			TargetPath		string	`json:"target_path"`
			UseTargetList		bool	`json:"use_target_list"`
			CacheDisabled		bool	`json:"cache_disabled"`
			CacheTimeout		int64	`json:"cache_timeout"`
			EndpointReturnsList	bool	`json:"endpoint_returns_list"`
		},
		"recheck_wait": int,
	}
}
```

- HostCheckObject: https://docs.incubator.to/github.com/TykTechnologies/tyk/apidef#HostCheckObject
- UptimeTests: https://docs.incubator.to/github.com/TykTechnologies/tyk/apidef#UptimeTests

Code is 2015-2017.

UptimeTestsConfig:

Conditions:
- if an onhostdown event it triggered
- if service discovery is enabled
- initiate a reset
- contact service discovery for all of it based on API ID.
- use `recheck_wait` from above.

HostCheckerManager uses servicediscovery, but is not clear why someone
would need to configure it separately. As the configuration matches
proxy.service_discovery, it would be possible to use that if not
configured (or omitted.).

The way the service discovery config is used is identical to the proxy
service, using a shared ServiceDiscovery{} utility object. Using service
discovery allows to coordinate healthchecks so that the testing is more
optimal, knows to which hosts to map API IDs.

Supposedly uptime tests could be aimed at a subset or a canary deployment,
and arguably, they may not even work:

Other reading:

Service Discovery: https://tyk.io/docs/tyk-self-managed/#service-discovery

This contains a fair bit of docs on configuring uptime tests, not the expected location.
Search for "Conduct uptime tests" and keep reading. It also seems to document
a fair bit of fiction as more than half of the fields don't exist.

- missing `disable`, `poller_group`, ...
- heavily outdated or we dropped a lot of it over time

- https://github.com/TykTechnologies/tyk/issues/3367
