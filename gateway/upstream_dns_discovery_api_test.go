package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// The valid shape has load balancing on and no static targets, which a rule
// counting targets reads as all weights zero and refuses.

// The two combination flags are under the test's control.
func dnsDiscoveryClassicAPI(apiID, listenPath string, loadBalancing, serviceDiscovery bool) *apidef.APIDefinition {
	def := apidef.DummyAPI()
	def.APIID = apiID
	def.Name = apiID
	def.Proxy.ListenPath = listenPath
	def.Proxy.TargetURL = "h2c://my-grpc-svc:9002"
	def.Proxy.EnableLoadBalancing = loadBalancing
	def.Proxy.ServiceDiscovery.UseDiscoveryService = serviceDiscovery
	def.Proxy.DNSDiscovery = apidef.DNSDiscoveryConfig{
		Enabled:         true,
		RefreshInterval: 10,
		StaleTTL:        300,
		DrainDeadline:   30,
	}
	return &def
}

// dnsDiscoveryOASAPI is the same API as a Tyk OAS document.
func dnsDiscoveryOASAPI(name, listenPath string, loadBalancing, serviceDiscovery bool) *oas.OAS {
	upstream := oas.Upstream{
		URL:          "h2c://my-grpc-svc:9002",
		DNSDiscovery: &oas.DNSDiscovery{Enabled: true, RefreshInterval: 10, StaleTTL: 300, DrainDeadline: 30},
	}
	if loadBalancing {
		upstream.LoadBalancing = &oas.LoadBalancing{Enabled: true}
	}
	if serviceDiscovery {
		upstream.ServiceDiscovery = &oas.ServiceDiscovery{
			Enabled:       true,
			QueryEndpoint: "http://consul:8500/v1/catalog/service/my-grpc-svc",
		}
	}

	document := &oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: name, Version: "1"},
			Paths:   openapi3.NewPaths(),
		},
	}
	document.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: name, State: oas.State{Active: true}},
		Upstream: upstream,
		Server:   oas.Server{ListenPath: oas.ListenPath{Value: listenPath, Strip: true}},
	})
	return document
}

// /tyk/apis has no schema, so its rule set is all that stands between an
// operator and a definition that cannot work.
func TestDNSDiscovery_ClassicEndpointRefusesTheTwoCombinations(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("without load balancing", func(t *testing.T) {
		def := dnsDiscoveryClassicAPI("dns-no-lb", "/dns-no-lb/", false, false)
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: def,
			BodyMatch: apidef.ErrDNSDiscoveryRequiresLoadBalancing.Error(),
			Code:      http.StatusBadRequest,
		})
	})

	t.Run("alongside service discovery", func(t *testing.T) {
		def := dnsDiscoveryClassicAPI("dns-and-sd", "/dns-and-sd/", true, true)
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: def,
			BodyMatch: apidef.ErrDNSDiscoveryWithServiceDiscovery.Error(),
			Code:      http.StatusBadRequest,
		})
	})

	t.Run("accepted, then refused on update", func(t *testing.T) {
		def := dnsDiscoveryClassicAPI("dns-classic-ok", "/dns-classic-ok/", true, false)

		// No targets at all, which the weight rule reads as all zero.
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis", Data: def,
			Code: http.StatusOK,
		})

		// The update handler looks the API up in the register.
		ts.Gw.DoReload()

		// An update that breaks a rule is refused just as a create is.
		def.Proxy.EnableLoadBalancing = false
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPut, Path: "/tyk/apis/dns-classic-ok", Data: def,
			BodyMatch: apidef.ErrDNSDiscoveryRequiresLoadBalancing.Error(),
			Code:      http.StatusBadRequest,
		})
	})
}

// On /tyk/apis/oas the rules apply to the document before it is converted.
func TestDNSDiscovery_OASEndpointRefusesTheTwoCombinations(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("without load balancing", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis/oas",
			Data:      dnsDiscoveryOASAPI("dns-oas-no-lb", "/dns-oas-no-lb/", false, false),
			BodyMatch: `upstream.loadBalancing must be enabled too`,
			Code:      http.StatusBadRequest,
		})
	})

	t.Run("alongside service discovery", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis/oas",
			Data:      dnsDiscoveryOASAPI("dns-oas-sd", "/dns-oas-sd/", true, true),
			BodyMatch: `cannot be enabled together`,
			Code:      http.StatusBadRequest,
		})
	})

	// The conversion used to drop loadBalancing.enabled with no targets under
	// it, so the API loaded with discovery switched back off.
	t.Run("accepted, and keeps load balancing through the conversion", func(t *testing.T) {
		document := dnsDiscoveryOASAPI("dns-oas-ok", "/dns-oas-ok/", true, false)

		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Method: http.MethodPost, Path: "/tyk/apis/oas", Data: document,
			Code: http.StatusOK,
		})

		var converted apidef.APIDefinition
		converted.SetDisabledFlags()
		document.ExtractTo(&converted)

		if !converted.Proxy.EnableLoadBalancing {
			t.Error("the accepted document converts to a definition with load balancing off, " +
				"so the gateway would refuse to source its target list from DNS")
		}
		if !converted.Proxy.DNSDiscovery.Enabled {
			t.Error("dns_discovery did not survive the conversion")
		}
	})
}
