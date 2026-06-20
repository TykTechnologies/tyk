package oas

import (
	"crypto/tls"
	"net/http"
	"sort"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// Verifies: SYS-REQ-104, SW-REQ-093
// SW-REQ-093:nominal:nominal
// SW-REQ-093:boundary:nominal
// SW-REQ-093:error_handling:nominal
// SW-REQ-093:error_handling:negative
// SW-REQ-093:determinism:nominal
func TestUpstreamDocumentHelpersPreserveSupportBehavior(t *testing.T) {
	t.Run("aggregate fill and extract preserve upstream support shape", func(t *testing.T) {
		api := apidef.APIDefinition{
			UpstreamCertificatesDisabled: false,
			UpstreamCertificates: map[string]string{
				"api.example.com:443": "cert-a",
			},
			CertificatePinningDisabled: false,
			PinnedPublicKeys: map[string]string{
				"api.example.com": "key-a, key-b",
			},
			GlobalRateLimit: apidef.GlobalRateLimit{Disabled: false, Rate: 42, Per: 60},
			Proxy: apidef.ProxyConfig{
				TargetURL:                   "https://upstream.example.com/base",
				PreserveHostHeader:          true,
				DisableStripSlash:           true,
				EnableLoadBalancing:         true,
				CheckHostAgainstUptimeTests: true,
				Targets: []string{
					"https://upstream-a.example.com",
					"https://upstream-a.example.com",
					"https://upstream-b.example.com",
				},
				ServiceDiscovery: apidef.ServiceDiscoveryConfiguration{
					UseDiscoveryService: true,
					QueryEndpoint:       "https://consul.example.com/v1/catalog",
					DataPath:            "node.value",
					UseNestedQuery:      true,
					ParentDataPath:      "node",
					PortDataPath:        "port",
					TargetPath:          "/health",
					UseTargetList:       true,
					CacheTimeout:        30,
					EndpointReturnsList: true,
				},
			},
			RequestSigning: apidef.RequestSigningMeta{
				IsEnabled:       true,
				SignatureHeader: "X-Signature",
				Algorithm:       "hmac-sha256",
				KeyId:           "key-1",
				HeaderList:      []string{"date", "host"},
				Secret:          "shared-secret",
				CertificateId:   "cert-1",
			},
			UpstreamAuth: apidef.UpstreamAuth{
				Enabled: true,
				BasicAuth: apidef.UpstreamBasicAuth{
					Enabled:  true,
					Username: "basic-user",
					Password: "basic-pass",
					Header:   apidef.AuthSource{Enabled: true, Name: "X-Basic"},
				},
				OAuth: apidef.UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{"client_credentials", "password"},
					ClientCredentials: apidef.ClientCredentials{
						ClientAuthData: apidef.ClientAuthData{ClientID: "client-id", ClientSecret: "client-secret"},
						Header:         apidef.AuthSource{Enabled: true, Name: "X-OAuth"},
						TokenURL:       "https://issuer.example.com/token",
						Scopes:         []string{"read", "write"},
						ExtraMetadata:  []string{"tenant"},
					},
					PasswordAuthentication: apidef.PasswordAuthentication{
						ClientAuthData: apidef.ClientAuthData{ClientID: "password-client", ClientSecret: "password-secret"},
						Header:         apidef.AuthSource{Enabled: true, Name: "X-Password"},
						Username:       "resource-user",
						Password:       "resource-pass",
						TokenURL:       "https://issuer.example.com/password",
						Scopes:         []string{"resource"},
						ExtraMetadata:  []string{"role"},
					},
				},
			},
			UptimeTests: apidef.UptimeTests{
				Disabled: false,
				Config: apidef.UptimeTestsConfig{
					ExpireUptimeAnalyticsAfter: 3600,
					RecheckWait:                15,
					ServiceDiscovery: apidef.ServiceDiscoveryConfiguration{
						UseDiscoveryService: true,
						QueryEndpoint:       "https://consul.example.com/v1/health",
						CacheTimeout:        12,
					},
				},
				CheckList: []apidef.HostCheckObject{{
					CheckURL:            "https://old.example.com/health",
					Protocol:            "tcp",
					Timeout:             750 * stdtime.Millisecond,
					EnableProxyProtocol: true,
					Method:              http.MethodPost,
					Headers:             map[string]string{"X-Probe": "true"},
					Body:                "ping",
					Commands:            []apidef.CheckCommand{{Name: "send", Message: "ping"}},
				}},
			},
		}
		api.Proxy.Transport.SSLInsecureSkipVerify = true
		api.Proxy.Transport.SSLCipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
		api.Proxy.Transport.SSLMinVersion = tls.VersionTLS12
		api.Proxy.Transport.SSLMaxVersion = tls.VersionTLS13
		api.Proxy.Transport.SSLForceCommonNameCheck = true
		api.Proxy.Transport.ProxyURL = "http://proxy.example.com:8080"

		var upstream Upstream
		upstream.Fill(api)

		assert.Equal(t, api.Proxy.TargetURL, upstream.URL)
		require.NotNil(t, upstream.ServiceDiscovery)
		assert.True(t, upstream.ServiceDiscovery.Enabled)
		require.NotNil(t, upstream.ServiceDiscovery.Cache)
		assert.Equal(t, int64(30), upstream.ServiceDiscovery.Cache.Timeout)
		require.NotNil(t, upstream.UptimeTests)
		assert.True(t, upstream.UptimeTests.Enabled)
		assert.Equal(t, tyktime.ReadableDuration(15*stdtime.Second), upstream.UptimeTests.HostDownRetestPeriod)
		require.Len(t, upstream.UptimeTests.Tests, 1)
		assert.Equal(t, "tcp://old.example.com/health", upstream.UptimeTests.Tests[0].CheckURL)
		require.NotNil(t, upstream.MutualTLS)
		assert.True(t, upstream.MutualTLS.Enabled)
		require.NotNil(t, upstream.CertificatePinning)
		assert.True(t, upstream.CertificatePinning.Enabled)
		require.NotNil(t, upstream.RateLimit)
		assert.Equal(t, ReadableDuration(stdtime.Minute), upstream.RateLimit.Per)
		require.NotNil(t, upstream.Authentication)
		require.NotNil(t, upstream.Authentication.BasicAuth)
		require.NotNil(t, upstream.Authentication.OAuth)
		require.NotNil(t, upstream.Authentication.RequestSigning)
		require.NotNil(t, upstream.TLSTransport)
		assert.Equal(t, "1.2", upstream.TLSTransport.MinVersion)
		assert.Equal(t, "1.3", upstream.TLSTransport.MaxVersion)
		require.NotNil(t, upstream.Proxy)
		assert.Equal(t, "http://proxy.example.com:8080", upstream.Proxy.URL)
		require.NotNil(t, upstream.LoadBalancing)
		assert.Equal(t, []LoadBalancingTarget{
			{URL: "https://upstream-a.example.com", Weight: 2},
			{URL: "https://upstream-b.example.com", Weight: 1},
		}, upstream.LoadBalancing.Targets)
		require.NotNil(t, upstream.PreserveHostHeader)
		require.NotNil(t, upstream.PreserveTrailingSlash)

		var extracted apidef.APIDefinition
		upstream.ExtractTo(&extracted)

		assert.Equal(t, api.Proxy.TargetURL, extracted.Proxy.TargetURL)
		assert.Equal(t, api.Proxy.ServiceDiscovery.QueryEndpoint, extracted.Proxy.ServiceDiscovery.QueryEndpoint)
		assert.False(t, extracted.Proxy.ServiceDiscovery.CacheDisabled)
		assert.Equal(t, int64(30), extracted.Proxy.ServiceDiscovery.CacheTimeout)
		assert.Equal(t, []string{
			"https://upstream-a.example.com",
			"https://upstream-a.example.com",
			"https://upstream-b.example.com",
		}, extracted.Proxy.Targets)
		assert.True(t, extracted.Proxy.PreserveHostHeader)
		assert.True(t, extracted.Proxy.DisableStripSlash)
		assert.Equal(t, tls.VersionTLS12, int(extracted.Proxy.Transport.SSLMinVersion))
		assert.Equal(t, tls.VersionTLS13, int(extracted.Proxy.Transport.SSLMaxVersion))
		assert.Equal(t, "http://proxy.example.com:8080", extracted.Proxy.Transport.ProxyURL)
		assert.Equal(t, map[string]string{"api.example.com:443": "cert-a"}, extracted.UpstreamCertificates)
		assert.Equal(t, map[string]string{"api.example.com": "key-a,key-b"}, extracted.PinnedPublicKeys)
		assert.Equal(t, float64(42), extracted.GlobalRateLimit.Rate)
		assert.Equal(t, float64(60), extracted.GlobalRateLimit.Per)
		assert.True(t, extracted.UpstreamAuth.Enabled)
		assert.Equal(t, "basic-user", extracted.UpstreamAuth.BasicAuth.Username)
		assert.Equal(t, "client-id", extracted.UpstreamAuth.OAuth.ClientCredentials.ClientID)
		assert.Equal(t, "resource-user", extracted.UpstreamAuth.OAuth.PasswordAuthentication.Username)
		assert.Equal(t, api.RequestSigning, extracted.RequestSigning)
		require.Len(t, extracted.UptimeTests.CheckList, 1)
		assert.Equal(t, "tcp", extracted.UptimeTests.CheckList[0].Protocol)
		assert.Equal(t, "tcp://old.example.com/health", extracted.UptimeTests.CheckList[0].CheckURL)
		assert.Equal(t, int64(3600), extracted.UptimeTests.Config.ExpireUptimeAnalyticsAfter)
	})

	t.Run("leaf helpers preserve boundary conversion behavior", func(t *testing.T) {
		tlsTransport := &TLSTransport{}
		tlsVersions := []struct {
			name  string
			text  string
			value uint16
		}{
			{name: "tls10", text: "1.0", value: tls.VersionTLS10},
			{name: "tls11", text: "1.1", value: tls.VersionTLS11},
			{name: "tls12", text: "1.2", value: tls.VersionTLS12},
			{name: "tls13", text: "1.3", value: tls.VersionTLS13},
			{name: "unknown", text: "", value: 0},
		}
		for _, tt := range tlsVersions {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.value, tlsTransport.tlsVersionFromString(tt.text))
				assert.Equal(t, tt.text, tlsTransport.tlsVersionToString(tt.value))
			})
		}

		cacheCases := []struct {
			name    string
			input   ServiceDiscovery
			timeout int64
			enabled bool
		}{
			{name: "new cache wins", input: ServiceDiscovery{CacheTimeout: 10, Cache: &ServiceDiscoveryCache{Enabled: true, Timeout: 20}}, timeout: 20, enabled: true},
			{name: "new cache disabled", input: ServiceDiscovery{CacheTimeout: 10, Cache: &ServiceDiscoveryCache{}}, timeout: 0, enabled: false},
			{name: "legacy cache", input: ServiceDiscovery{CacheTimeout: 15}, timeout: 15, enabled: true},
			{name: "empty cache", input: ServiceDiscovery{}, timeout: 0, enabled: false},
		}
		for _, tt := range cacheCases {
			t.Run(tt.name, func(t *testing.T) {
				timeout, enabled := tt.input.CacheOptions()
				assert.Equal(t, tt.timeout, timeout)
				assert.Equal(t, tt.enabled, enabled)
			})
		}

		urlCases := []struct {
			name         string
			protocol     string
			checkURL     string
			filled       string
			classicProto string
			classicURL   string
		}{
			{name: "replace conflicting protocol", protocol: "tcp", checkURL: "https://example.com/health", filled: "tcp://example.com/health", classicProto: "tcp", classicURL: "tcp://example.com/health"},
			{name: "preserve empty protocol input", checkURL: "example.com/health", filled: "example.com/health", classicURL: "example.com/health"},
		}
		for _, tt := range urlCases {
			t.Run(tt.name, func(t *testing.T) {
				uptime := &UptimeTests{}
				assert.Equal(t, tt.filled, uptime.fillCheckURL(tt.protocol, tt.checkURL))
				protocol, checkURL := uptime.extractToProtocolAndCheckURL(tt.filled)
				assert.Equal(t, tt.classicProto, protocol)
				assert.Equal(t, tt.classicURL, checkURL)
			})
		}

		test := &UptimeTest{}
		test.AddCommand("send", "ping")
		test.AddCommand("expect", "pong")
		assert.Equal(t, []UptimeTestCommand{{Name: "send", Message: "ping"}, {Name: "expect", Message: "pong"}}, test.Commands)
	})

	t.Run("load balancing preserves deterministic weights and zero weight targets", func(t *testing.T) {
		existing := LoadBalancing{
			Targets: []LoadBalancingTarget{
				{URL: "https://disabled.example.com", Weight: 0},
				{URL: "https://old-active.example.com", Weight: 4},
			},
		}
		existing.Fill(apidef.APIDefinition{Proxy: apidef.ProxyConfig{
			EnableLoadBalancing:         true,
			CheckHostAgainstUptimeTests: true,
			Targets: []string{
				"https://active.example.com",
				"https://active.example.com",
				"https://other.example.com",
			},
		}})

		assert.True(t, existing.Enabled)
		assert.True(t, existing.SkipUnavailableHosts)
		assert.Equal(t, []LoadBalancingTarget{
			{URL: "https://active.example.com", Weight: 2},
			{URL: "https://disabled.example.com", Weight: 0},
			{URL: "https://other.example.com", Weight: 1},
		}, existing.Targets)

		var extracted apidef.APIDefinition
		existing.ExtractTo(&extracted)
		assert.Equal(t, []string{
			"https://active.example.com",
			"https://active.example.com",
			"https://other.example.com",
		}, extracted.Proxy.Targets)

		empty := LoadBalancing{Enabled: true, SkipUnavailableHosts: true}
		empty.Fill(apidef.APIDefinition{Proxy: apidef.ProxyConfig{EnableLoadBalancing: true}})
		assert.True(t, empty.Enabled)
		assert.True(t, empty.SkipUnavailableHosts)
		assert.Nil(t, empty.Targets)
	})

	t.Run("pinning and certificate mappings are stable local shape conversions", func(t *testing.T) {
		keys := PinnedPublicKeys(make([]PinnedPublicKey, 2))
		keys.Fill(map[string]string{
			"b.example.com": "key-b-1, key-b-2",
			"a.example.com": "key-a",
		})
		assert.Equal(t, PinnedPublicKeys{
			{Domain: "a.example.com", PublicKeys: []string{"key-a"}},
			{Domain: "b.example.com", PublicKeys: []string{"key-b-1", "key-b-2"}},
		}, keys)

		extractedKeys := map[string]string{}
		keys.ExtractTo(extractedKeys)
		assert.Equal(t, map[string]string{"a.example.com": "key-a", "b.example.com": "key-b-1,key-b-2"}, extractedKeys)

		mtls := MutualTLS{Enabled: true, DomainToCertificates: []DomainToCertificate{{Domain: "api.example.com", Certificate: "cert-a"}}}
		var api apidef.APIDefinition
		mtls.ExtractTo(&api)
		assert.False(t, api.UpstreamCertificatesDisabled)
		assert.Equal(t, map[string]string{"api.example.com": "cert-a"}, api.UpstreamCertificates)

		certPinning := CertificatePinning{Enabled: false, DomainToPublicKeysMapping: keys}
		certPinning.ExtractTo(&api)
		assert.True(t, api.CertificatePinningDisabled)
		assert.Equal(t, map[string]string{"a.example.com": "key-a", "b.example.com": "key-b-1,key-b-2"}, api.PinnedPublicKeys)
	})

	t.Run("nil optional children extract through zero support shapes", func(t *testing.T) {
		upstream := Upstream{URL: "https://upstream.example.com"}
		var api apidef.APIDefinition

		upstream.ExtractTo(&api)

		assert.Nil(t, upstream.ServiceDiscovery)
		assert.Nil(t, upstream.UptimeTests)
		assert.Nil(t, upstream.MutualTLS)
		assert.Nil(t, upstream.CertificatePinning)
		assert.Nil(t, upstream.RateLimit)
		assert.Nil(t, upstream.Authentication)
		assert.Nil(t, upstream.LoadBalancing)
		assert.Nil(t, upstream.TLSTransport)
		assert.Nil(t, upstream.Proxy)
		assert.Nil(t, upstream.PreserveHostHeader)
		assert.Nil(t, upstream.PreserveTrailingSlash)
		assert.Equal(t, "https://upstream.example.com", api.Proxy.TargetURL)
		assert.True(t, api.Proxy.ServiceDiscovery.CacheDisabled)
		assert.True(t, api.UpstreamCertificatesDisabled)
		assert.True(t, api.CertificatePinningDisabled)
		assert.True(t, api.GlobalRateLimit.Disabled)
	})

	t.Run("leaf authentication helpers preserve nested upstream auth shapes", func(t *testing.T) {
		auth := UpstreamAuth{Enabled: true}
		auth.Fill(apidef.APIDefinition{UpstreamAuth: apidef.UpstreamAuth{
			Enabled: true,
			BasicAuth: apidef.UpstreamBasicAuth{
				Enabled:  true,
				Username: "user",
				Password: "pass",
				Header:   apidef.AuthSource{Enabled: true, Name: "X-Basic"},
			},
			OAuth: apidef.UpstreamOAuth{
				Enabled:               true,
				AllowedAuthorizeTypes: []string{"client_credentials"},
				ClientCredentials: apidef.ClientCredentials{
					ClientAuthData: apidef.ClientAuthData{ClientID: "client", ClientSecret: "secret"},
					Header:         apidef.AuthSource{Enabled: true, Name: "X-OAuth"},
					TokenURL:       "https://issuer.example/token",
					Scopes:         []string{"scope-a"},
					ExtraMetadata:  []string{"tenant"},
				},
				PasswordAuthentication: apidef.PasswordAuthentication{
					ClientAuthData: apidef.ClientAuthData{ClientID: "password-client"},
					Header:         apidef.AuthSource{Enabled: true, Name: "X-Password"},
					Username:       "resource-user",
					Password:       "resource-pass",
					TokenURL:       "https://issuer.example/password",
					Scopes:         []string{"scope-b"},
					ExtraMetadata:  []string{"role"},
				},
			},
		}})

		require.NotNil(t, auth.BasicAuth)
		require.NotNil(t, auth.OAuth)
		require.NotNil(t, auth.OAuth.ClientCredentials)
		require.NotNil(t, auth.OAuth.PasswordAuthentication)
		assert.Equal(t, "user", auth.BasicAuth.Username)
		assert.Equal(t, "client", auth.OAuth.ClientCredentials.ClientID)
		assert.Equal(t, "resource-user", auth.OAuth.PasswordAuthentication.Username)

		var extracted apidef.APIDefinition
		auth.ExtractTo(&extracted)
		assert.True(t, extracted.UpstreamAuth.Enabled)
		assert.Equal(t, "X-Basic", extracted.UpstreamAuth.BasicAuth.Header.Name)
		assert.Equal(t, "client", extracted.UpstreamAuth.OAuth.ClientCredentials.ClientID)
		assert.Equal(t, "password-client", extracted.UpstreamAuth.OAuth.PasswordAuthentication.ClientID)
	})

	t.Run("target ordering remains deterministic after fill", func(t *testing.T) {
		lb := LoadBalancing{}
		lb.Fill(apidef.APIDefinition{Proxy: apidef.ProxyConfig{Targets: []string{
			"https://c.example.com",
			"https://a.example.com",
			"https://c.example.com",
			"https://b.example.com",
		}}})

		got := append([]LoadBalancingTarget(nil), lb.Targets...)
		want := append([]LoadBalancingTarget(nil), lb.Targets...)
		sort.Slice(want, func(i, j int) bool { return want[i].URL < want[j].URL })
		assert.Equal(t, want, got)
	})
}
