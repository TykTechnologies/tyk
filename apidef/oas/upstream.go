package oas

import "github.com/TykTechnologies/tyk/apidef"

type Upstream struct {
	URL              string            `bson:"url" json:"url"` // required
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`
	Test             *Test             `bson:"test,omitempty" json:"test,omitempty"`
}

func (u *Upstream) Fill(api apidef.APIDefinition) {
	u.URL = api.Proxy.TargetURL

	if u.ServiceDiscovery == nil {
		u.ServiceDiscovery = &ServiceDiscovery{}
	}

	u.ServiceDiscovery.Fill(api.Proxy.ServiceDiscovery)
	if (*u.ServiceDiscovery == ServiceDiscovery{}) {
		u.ServiceDiscovery = nil
	}
}

func (u *Upstream) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.TargetURL = u.URL

	if u.ServiceDiscovery != nil {
		u.ServiceDiscovery.ExtractTo(&api.Proxy.ServiceDiscovery)
	}
}

type ServiceDiscovery struct {
	Enabled             bool   `bson:"enabled" json:"enabled"` // required
	EndpointReturnsList bool   `bson:"endpointReturnsList,omitempty" json:"endpointReturnsList,omitempty"`
	CacheTimeout        int64  `bson:"cacheTimeout,omitempty" json:"cacheTimeout,omitempty"`
	ParentDataPath      string `bson:"parentDataPath,omitempty" json:"parentDataPath,omitempty"`
	QueryEndpoint       string `bson:"queryEndpoint,omitempty" json:"queryEndpoint,omitempty"`
	TargetPath          string `bson:"targetPath,omitempty" json:"targetPath,omitempty"`
	UseTargetList       bool   `bson:"useTargetList,omitempty" json:"useTargetList,omitempty"`
	UseNestedQuery      bool   `bson:"useNestedQuery,omitempty" json:"useNestedQuery,omitempty"`
	DataPath            string `bson:"dataPath,omitempty" json:"dataPath,omitempty"`
	PortDataPath        string `bson:"portDataPath,omitempty" json:"portDataPath,omitempty"`
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
	ServiceDiscovery *ServiceDiscovery `bson:"serviceDiscovery,omitempty" json:"serviceDiscovery,omitempty"`
}

func (t *Test) Fill(uptimeTests apidef.UptimeTests) {
	if t.ServiceDiscovery == nil {
		t.ServiceDiscovery = &ServiceDiscovery{}
	}

	t.ServiceDiscovery.Fill(uptimeTests.Config.ServiceDiscovery)
	if (*t.ServiceDiscovery == ServiceDiscovery{}) {
		t.ServiceDiscovery = nil
	}
}

func (t *Test) ExtractTo(uptimeTests *apidef.UptimeTests) {
	if t.ServiceDiscovery != nil {
		t.ServiceDiscovery.ExtractTo(&uptimeTests.Config.ServiceDiscovery)
	}
}
