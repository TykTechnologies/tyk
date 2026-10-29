package gateway

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Certificate store IDs: an org ID followed by a SHA-256 fingerprint.
const (
	testCert  = "5f0c1a2b3c4d5e6f708192a3" + "1111111111111111111111111111111111111111111111111111111111111111"
	testOther = "5f0c1a2b3c4d5e6f708192a3" + "2222222222222222222222222222222222222222222222222222222222222222"
	testKeyA  = "5f0c1a2b3c4d5e6f708192a3" + "3333333333333333333333333333333333333333333333333333333333333333"
	testKeyB  = "5f0c1a2b3c4d5e6f708192a3" + "4444444444444444444444444444444444444444444444444444444444444444"
)

func reportOf(conf config.Config, specs ...*APISpec) []model.CertificateUsage {
	return collectCertUsage(&conf, specs).buildReport()
}

func reportedIDs(report []model.CertificateUsage) []string {
	ids := make([]string, 0, len(report))
	for _, c := range report {
		ids = append(ids, c.CertID)
	}
	return ids
}

func findReported(report []model.CertificateUsage, certID string) *model.CertificateUsage {
	for i := range report {
		if report[i].CertID == certID {
			return &report[i]
		}
	}
	return nil
}

func TestCertUsageReport_GatewayConfig(t *testing.T) {
	type tc struct {
		name    string
		conf    func(c *config.Config)
		specs   []*APISpec
		setting string
		used    bool
	}

	tlsAPI := func(protocol string, port int) *APISpec {
		return &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "tls-api", Protocol: protocol, ListenPort: port}}
	}
	mtlsAPI := func(protocol string, port int) *APISpec {
		spec := tlsAPI(protocol, port)
		spec.UseMutualTLSAuth = true
		return spec
	}

	tests := []tc{
		{
			name: "HTTPS certificate with use_ssl on",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.HttpServerOptions.SSLCertificates = []string{testCert}
			},
			setting: certSettingServer,
			used:    true,
		},
		{
			name:    "HTTPS certificate with use_ssl off and no TLS API",
			conf:    func(c *config.Config) { c.HttpServerOptions.SSLCertificates = []string{testCert} },
			setting: certSettingServer,
			used:    false,
		},
		{
			name:    "HTTPS certificate with a tls API on its own port",
			conf:    func(c *config.Config) { c.HttpServerOptions.SSLCertificates = []string{testCert} },
			specs:   []*APISpec{tlsAPI("tls", 9443)},
			setting: certSettingServer,
			used:    true,
		},
		{
			name:    "HTTPS certificate with an https API on its own port",
			conf:    func(c *config.Config) { c.HttpServerOptions.SSLCertificates = []string{testCert} },
			specs:   []*APISpec{tlsAPI("https", 9443)},
			setting: certSettingServer,
			used:    true,
		},
		{
			name:    "HTTPS certificate with a tls API on the Gateway's port",
			conf:    func(c *config.Config) { c.HttpServerOptions.SSLCertificates = []string{testCert} },
			specs:   []*APISpec{tlsAPI("tls", 8080)},
			setting: certSettingServer,
			used:    false,
		},
		{
			name:    "client CA for all APIs with a client mTLS API on its own TLS port",
			conf:    func(c *config.Config) { c.Security.Certificates.API = []string{testCert} },
			specs:   []*APISpec{mtlsAPI("tls", 9443)},
			setting: certSettingAPIs,
			used:    true,
		},
		{
			name: "client CA for all APIs with a client mTLS API and use_ssl on",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.Certificates.API = []string{testCert}
			},
			specs:   []*APISpec{mtlsAPI("", 0)},
			setting: certSettingAPIs,
			used:    true,
		},
		{
			name: "client CA for all APIs with TLS but no client mTLS API",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.Certificates.API = []string{testCert}
			},
			specs:   []*APISpec{tlsAPI("", 0)},
			setting: certSettingAPIs,
			used:    false,
		},
		{
			name:    "client CA for all APIs with a client mTLS API served over plain HTTP",
			conf:    func(c *config.Config) { c.Security.Certificates.API = []string{testCert} },
			specs:   []*APISpec{mtlsAPI("", 0)},
			setting: certSettingAPIs,
			used:    false,
		},
		{
			name: "control API mTLS with use_ssl off and a TLS API on its own port",
			conf: func(c *config.Config) {
				c.Security.ControlAPIUseMutualTLS = true
				c.Security.Certificates.ControlAPI = []string{testCert}
			},
			specs:   []*APISpec{tlsAPI("tls", 9443)},
			setting: certSettingControlAPI,
			used:    false,
		},
		{
			name: "storage service mTLS by ID, which the Gateway never reads",
			conf: func(c *config.Config) {
				c.ExternalServices.Storage.MTLS = config.MTLSConfig{Enabled: true, CertID: testCert}
			},
			used: false,
		},
		{
			name:    "a missing certificate file isn't reported",
			conf:    func(c *config.Config) { c.Security.Certificates.Upstream = map[string]string{"*": "/no/such/cert.pem"} },
			setting: certSettingUpstream,
			used:    false,
		},
		{
			name:    "client CA for all APIs without TLS",
			conf:    func(c *config.Config) { c.Security.Certificates.API = []string{testCert} },
			setting: certSettingAPIs,
			used:    false,
		},
		{
			name: "control API mTLS",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.ControlAPIUseMutualTLS = true
				c.Security.Certificates.ControlAPI = []string{testCert}
			},
			setting: certSettingControlAPI,
			used:    true,
		},
		{
			name: "control API mTLS switched off",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.Certificates.ControlAPI = []string{testCert}
			},
			setting: certSettingControlAPI,
			used:    false,
		},
		{
			name: "control API mTLS without TLS",
			conf: func(c *config.Config) {
				c.Security.ControlAPIUseMutualTLS = true
				c.Security.Certificates.ControlAPI = []string{testCert}
			},
			setting: certSettingControlAPI,
			used:    false,
		},
		{
			name:    "upstream mTLS for all upstreams, without TLS",
			conf:    func(c *config.Config) { c.Security.Certificates.Upstream = map[string]string{"*": testCert} },
			setting: certSettingUpstream,
			used:    true,
		},
		{
			name:    "pinned public keys, without TLS",
			conf:    func(c *config.Config) { c.Security.PinnedPublicKeys = map[string]string{"*": testCert} },
			setting: certSettingPinnedKeys,
			used:    true,
		},
		{
			name: "external service mTLS",
			conf: func(c *config.Config) {
				c.ExternalServices.Webhooks.MTLS = config.MTLSConfig{Enabled: true, CertID: testCert}
			},
			setting: "external_services.webhooks.mtls",
			used:    true,
		},
		{
			name: "external service CA",
			conf: func(c *config.Config) {
				c.ExternalServices.OAuth.MTLS = config.MTLSConfig{Enabled: true, CACertIDs: []string{testOther, testCert}}
			},
			setting: "external_services.oauth.mtls",
			used:    true,
		},
		{
			name: "external service mTLS switched off",
			conf: func(c *config.Config) {
				c.ExternalServices.Storage.MTLS = config.MTLSConfig{CertID: testCert, CACertIDs: []string{testCert}}
			},
			setting: "external_services.storage.mtls",
			used:    false,
		},
		{
			name: "Dashboard API certificates are never read",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.Certificates.Dashboard = []string{testCert}
			},
			used:  false,
			specs: nil,
		},
		{
			name: "MDCB API certificates are never read",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.Security.Certificates.MDCB = []string{testCert}
			},
			used: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.Config{ListenPort: 8080}
			tc.conf(&conf)

			got := findReported(reportOf(conf, tc.specs...), testCert)
			if !tc.used {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, []string{tc.setting}, got.GatewayConfig)
			assert.Empty(t, got.APIIDs)
		})
	}

	t.Run("pinned public keys listing several keys", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.PinnedPublicKeys = map[string]string{"*": testKeyA + "," + testKeyB}

		assert.Equal(t, []string{testKeyA, testKeyB}, reportedIDs(reportOf(conf)))
	})

	t.Run("one certificate used by several settings and an API", func(t *testing.T) {
		conf := config.Config{}
		conf.HttpServerOptions.UseSSL = true
		conf.HttpServerOptions.SSLCertificates = []string{testCert}
		conf.Security.Certificates.Upstream = map[string]string{"*": testCert}
		spec := createTestAPISpec("api1", nil, nil, map[string]string{"*": testCert}, nil)

		report := reportOf(conf, spec)
		require.Len(t, report, 1)
		assert.Equal(t, model.CertificateUsage{
			CertID:        testCert,
			GatewayConfig: []string{certSettingServer, certSettingUpstream},
			APIIDs:        []string{"api1"},
		}, report[0])
	})
}

func TestCertUsageReport_APIs(t *testing.T) {
	classic := func(active bool, mutate func(a *apidef.APIDefinition)) *APISpec {
		a := &apidef.APIDefinition{APIID: "classic", Active: true}
		mutate(a)
		if !active {
			a.UseMutualTLSAuth = false
			a.UpstreamCertificatesDisabled = true
			a.DomainDisabled = true
			a.CertificatePinningDisabled = true
			a.RequestSigning.IsEnabled = false
		}
		return &APISpec{APIDefinition: a}
	}

	uses := map[string]func(a *apidef.APIDefinition){
		"client mTLS": func(a *apidef.APIDefinition) {
			a.UseMutualTLSAuth = true
			a.ClientCertificates = []string{testCert}
		},
		"upstream mTLS": func(a *apidef.APIDefinition) {
			a.UpstreamCertificates = map[string]string{"*": testCert}
		},
		"custom domain": func(a *apidef.APIDefinition) {
			a.Certificates = []string{testCert}
		},
		"pinning": func(a *apidef.APIDefinition) {
			a.PinnedPublicKeys = map[string]string{"*": testOther + "," + testCert}
		},
		"request signing": func(a *apidef.APIDefinition) {
			a.RequestSigning = apidef.RequestSigningMeta{IsEnabled: true, Algorithm: "rsa-sha256", KeyId: "key", CertificateId: testCert}
		},
	}

	for name, mutate := range uses {
		t.Run(name+" active", func(t *testing.T) {
			conf := config.Config{}
			conf.HttpServerOptions.UseSSL = true // custom domain certificates need a TLS listener
			got := findReported(reportOf(conf, classic(true, mutate)), testCert)
			require.NotNil(t, got)
			assert.Equal(t, []string{"classic"}, got.APIIDs)
			assert.Empty(t, got.GatewayConfig)
		})

		t.Run(name+" switched off", func(t *testing.T) {
			conf := config.Config{}
			spec := classic(false, mutate)

			assert.Nil(t, findReported(reportOf(conf, spec), testCert), "an inactive use isn't reported")
			assert.Contains(t, collectCertUsage(&conf, []*APISpec{spec}).references, testCert, "an inactive use still counts for sync")
		})
	}

	t.Run("custom domain certificates are only used by a TLS listener", func(t *testing.T) {
		spec := classic(true, uses["custom domain"])
		assert.Empty(t, reportOf(config.Config{}, spec), "the API is served over plain HTTP")

		conf := config.Config{}
		conf.HttpServerOptions.UseSSL = true
		assert.Equal(t, []string{testCert}, reportedIDs(reportOf(conf, spec)))

		spec.Protocol = "https"
		spec.ListenPort = 9443
		assert.Equal(t, []string{testCert}, reportedIDs(reportOf(config.Config{}, spec)), "the API listens with https on its own port")

		assert.Contains(t, collectCertUsage(&config.Config{}, []*APISpec{classic(true, uses["custom domain"])}).references, testCert,
			"selective sync still downloads them")
	})

	t.Run("loaded API whose active flag is off", func(t *testing.T) {
		// The Gateway serves every API it loads, so its uses count whatever the active flag says.
		spec := classic(true, uses["client mTLS"])
		spec.Active = false

		assert.Equal(t, []string{testCert}, reportedIDs(reportOf(config.Config{}, spec)))
	})

	t.Run("pin list with several keys", func(t *testing.T) {
		spec := classic(true, uses["pinning"])

		report := reportOf(config.Config{}, spec)
		assert.Equal(t, []string{testCert, testOther}, reportedIDs(report))

		refs := collectCertUsage(&config.Config{}, []*APISpec{spec}).references
		assert.Contains(t, refs, testCert)
		assert.Contains(t, refs, testOther)
		assert.NotContains(t, refs, testOther+","+testCert)
	})

	oasSpec := func(teEnabled bool) *APISpec {
		x := &oas.XTykAPIGateway{}
		x.Info.State.Active = true
		x.Server.Authentication = &oas.Authentication{
			Enabled: true,
			SecuritySchemes: oas.SecuritySchemes{
				"oauth": &oas.OAuth2{
					Enabled: true,
					TokenExchange: &oas.OAuth2TokenExchange{
						Enabled: teEnabled,
						Providers: []oas.OAuth2TokenExchangeProvider{{
							Name:       "idp",
							ClientAuth: &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPrivateKeyJWT, CertID: testCert},
						}},
					},
				},
			},
		}

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "oas", IsOAS: true, Active: true}}
		spec.OAS.SetTykExtension(x)
		return spec
	}

	t.Run("token exchange provider", func(t *testing.T) {
		got := findReported(reportOf(config.Config{}, oasSpec(true)), testCert)
		require.NotNil(t, got)
		assert.Equal(t, []string{"oas"}, got.APIIDs)
	})

	t.Run("token exchange switched off", func(t *testing.T) {
		conf := config.Config{}
		assert.Empty(t, reportOf(conf, oasSpec(false)))
		assert.Contains(t, collectCertUsage(&conf, []*APISpec{oasSpec(false)}).references, testCert)
	})
}

func TestCertUsageReport_FileAndInline(t *testing.T) {
	certPEM, _, combinedPEM, tlsCert := crypto.GenServerCertificate()
	fingerprint := certs.HexSHA256(tlsCert.Certificate[0])

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubFingerprint := certs.HexSHA256(pubDER)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "upstream.pem")
	require.NoError(t, os.WriteFile(certFile, combinedPEM, 0o600))
	pubFile := filepath.Join(dir, "pin.pem")
	require.NoError(t, os.WriteFile(pubFile, pubPEM, 0o600))

	t.Run("certificate file", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.Certificates.Upstream = map[string]string{"*": certFile}

		report := reportOf(conf)
		assert.Equal(t, []string{fingerprint}, reportedIDs(report))
		assert.Equal(t, []string{certSettingUpstream}, report[0].GatewayConfig)
	})

	t.Run("inline certificate", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.Certificates.Upstream = map[string]string{"*": string(certPEM)}

		assert.Equal(t, []string{fingerprint}, reportedIDs(reportOf(conf)))
		assert.Empty(t, collectCertUsage(&conf, nil).references, "an inline certificate isn't synced")
	})

	t.Run("public key file for pinning", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.PinnedPublicKeys = map[string]string{"*": pubFile}

		assert.Equal(t, []string{pubFingerprint}, reportedIDs(reportOf(conf)))
	})

	t.Run("unreadable inline value isn't reported", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.Certificates.Upstream = map[string]string{"*": "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"}

		assert.Empty(t, reportOf(conf))
	})
}

func TestCertUsageReport_FileOnlySettings(t *testing.T) {
	_, _, combinedPEM, tlsCert := crypto.GenServerCertificate()
	fingerprint := certs.HexSHA256(tlsCert.Certificate[0])
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certFile, combinedPEM, 0o600))

	fileMTLS := config.MTLSConfig{Enabled: true, CertFile: certFile, KeyFile: certFile}
	redisTLS := func(c *config.Config) {
		c.Storage.Type = "redis"
		c.Storage.UseSSL = true
	}

	tests := []struct {
		name    string
		conf    func(c *config.Config)
		setting string
		used    bool
	}{
		{
			name: "HTTPS certificate file with use_ssl on",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.HttpServerOptions.Certificates = []config.CertData{{Name: "example.com", CertFile: certFile, KeyFile: certFile}}
			},
			setting: certSettingServerFile,
			used:    true,
		},
		{
			name: "HTTPS certificate file without TLS",
			conf: func(c *config.Config) {
				c.HttpServerOptions.Certificates = []config.CertData{{CertFile: certFile, KeyFile: certFile}}
			},
			used: false,
		},
		{
			name: "HTTPS certificate file without a key file",
			conf: func(c *config.Config) {
				c.HttpServerOptions.UseSSL = true
				c.HttpServerOptions.Certificates = []config.CertData{{CertFile: certFile}}
			},
			used: false,
		},
		{
			name:    "external service certificate file",
			conf:    func(c *config.Config) { c.ExternalServices.Webhooks.MTLS = fileMTLS },
			setting: "external_services.webhooks.mtls",
			used:    true,
		},
		{
			name: "external service CA file",
			conf: func(c *config.Config) {
				c.ExternalServices.OAuth.MTLS = config.MTLSConfig{Enabled: true, CAFile: certFile}
			},
			setting: "external_services.oauth.mtls",
			used:    true,
		},
		{
			name: "external service CA file overridden by CA certificate IDs",
			conf: func(c *config.Config) {
				c.ExternalServices.OAuth.MTLS = config.MTLSConfig{Enabled: true, CAFile: certFile, CACertIDs: []string{testOther}}
			},
			used: false,
		},
		{
			name: "external service mTLS switched off",
			conf: func(c *config.Config) {
				mtls := fileMTLS
				mtls.Enabled = false
				mtls.CAFile = certFile
				c.ExternalServices.Health.MTLS = mtls
			},
			used: false,
		},
		{
			name: "storage service files with Redis TLS",
			conf: func(c *config.Config) {
				redisTLS(c)
				c.ExternalServices.Storage.MTLS = fileMTLS
			},
			setting: "external_services.storage.mtls",
			used:    true,
		},
		{
			name: "storage service CA file with Redis TLS",
			conf: func(c *config.Config) {
				redisTLS(c)
				c.ExternalServices.Storage.MTLS = config.MTLSConfig{Enabled: true, CAFile: certFile}
			},
			setting: "external_services.storage.mtls",
			used:    true,
		},
		{
			name: "storage service files without Redis TLS",
			conf: func(c *config.Config) {
				c.Storage.Type = "redis"
				c.ExternalServices.Storage.MTLS = fileMTLS
			},
			used: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.Config{ListenPort: 8080}
			tc.conf(&conf)

			usage := collectCertUsage(&conf, nil)
			assert.NotContains(t, usage.references, certFile, "file-only settings are never synced")

			got := findReported(usage.buildReport(), fingerprint)
			if !tc.used {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, []string{tc.setting}, got.GatewayConfig)
		})
	}

	t.Run("a missing file isn't reported", func(t *testing.T) {
		conf := config.Config{}
		conf.HttpServerOptions.UseSSL = true
		conf.HttpServerOptions.Certificates = []config.CertData{{CertFile: "/no/such/cert.pem", KeyFile: "/no/such/key.pem"}}

		assert.Empty(t, reportOf(conf))
	})
}

func TestCertUsageReport_EveryGatewayAndReload(t *testing.T) {
	_, _, combinedPEM, _ := crypto.GenServerCertificate()

	ts := StartTest(nil)
	defer ts.Close()

	require.NotNil(t, ts.Gw.certUsageTracker, "every Gateway tracks the certificates it uses")

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "org1")
	require.NoError(t, err)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "api-with-cert"
		spec.Proxy.ListenPath = "/with-cert"
		spec.UpstreamCertificates = map[string]string{"*": certID}
	})

	got := findReported(ts.Gw.certificateReport(), certID)
	require.NotNil(t, got)
	assert.Equal(t, []string{"api-with-cert"}, got.APIIDs)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "api-with-cert"
		spec.Proxy.ListenPath = "/with-cert"
		spec.UpstreamCertificates = map[string]string{"*": certID}
		spec.UpstreamCertificatesDisabled = true
	})

	assert.Nil(t, findReported(ts.Gw.certificateReport(), certID), "the report reflects the reloaded APIs")
	assert.True(t, ts.Gw.certUsageTracker.Required(certID), "a switched-off use is still synced")

	t.Run("a file certificate is reported by the fingerprint the store gives it", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "cert.pem")
		require.NoError(t, os.WriteFile(file, combinedPEM, 0o600))

		conf := config.Config{}
		conf.Security.Certificates.Upstream = map[string]string{"*": file}

		assert.Equal(t, []string{certID[len("org1"):]}, reportedIDs(reportOf(conf)))
	})
}

func TestCertUsage_SelectiveSyncIncludesGatewayConfig(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.Security.Certificates.Upstream = map[string]string{"*": "org1upstream"}
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.ClientCertificates = []string{"org1client"} // mTLS switched off
		spec.UseMutualTLSAuth = false
	})

	assert.True(t, ts.Gw.certUsageTracker.Required("org1upstream"), "a Gateway configuration certificate is synced")
	assert.True(t, ts.Gw.certUsageTracker.Required("org1client"), "a switched-off API use is synced")
	assert.Contains(t, ts.Gw.certUsageTracker.APIs("org1upstream"), gatewayConfigUser)
}
