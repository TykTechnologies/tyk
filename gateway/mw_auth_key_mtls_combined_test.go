package gateway

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestStaticAndDynamicMTLS tests the combination of static mTLS (client certificate allowlist)
// and dynamic mTLS (token-certificate binding) authentication.
// This test validates the scenario where:
// 1. The API has UseMutualTLSAuth enabled with a ClientCertificates allowlist (static mTLS)
// 2. The API also has UseCertificate enabled in auth config for dynamic token-cert binding
// 3. Both checks must pass for authentication to succeed
func TestStaticAndDynamicMTLS(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.AllowUnsafeDynamicMTLSToken = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create three different client certificates
	// Cert 1: will be in allowlist and bound to token
	clientCertPem1, _, _, clientCert1 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID1, err := ts.Gw.CertificateManager.Add(clientCertPem1, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID1, "default")
	certHash1 := "default" + certs.HexSHA256(clientCert1.Certificate[0])

	// Cert 2: will be in allowlist but NOT bound to token
	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID2, err := ts.Gw.CertificateManager.Add(clientCertPem2, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID2, "default")
	_ = "default" + certs.HexSHA256(clientCert2.Certificate[0]) // certHash2 used later

	// Cert 3: will NOT be in allowlist
	clientCertPem3, _, _, clientCert3 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID3, err := ts.Gw.CertificateManager.Add(clientCertPem3, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID3, "default")
	certHash3 := "default" + certs.HexSHA256(clientCert3.Certificate[0])

	// Create API with both static and dynamic mTLS enabled
	// - UseMutualTLSAuth + ClientCertificates = static mTLS with allowlist
	// - UseStandardAuth + UseCertificate = dynamic mTLS with token binding
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "combined-mtls-api"
		spec.OrgID = "default"
		// Enable static mTLS with allowlist (only cert1 and cert2 allowed)
		spec.UseMutualTLSAuth = true
		spec.ClientCertificates = []string{clientCertID1, clientCertID2}
		// Enable dynamic mTLS (token-certificate binding)
		spec.UseStandardAuth = true
		spec.UseKeylessAccess = false
		authConf := apidef.AuthConfig{
			Name:           "authToken",
			UseCertificate: true, // This enables dynamic mTLS
			AuthHeaderName: "Authorization",
		}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": authConf,
		}
		spec.Auth = authConf
		spec.Proxy.ListenPath = "/combined-mtls"
	})

	t.Run("Success: allowlisted cert with matching token binding", func(t *testing.T) {
		// Create session with certificate 1 hash bound to token
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.Certificate = clientCertID1 // Dynamic mTLS binding
		})

		assert.NotEmpty(t, key, "Should create key with certificate binding")

		// Request with cert1 (in allowlist and bound to token) should succeed
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/combined-mtls",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})

	t.Run("Legacy dynamic mTLS auto-updates session certificate", func(t *testing.T) {
		// In legacy mode (using session.Certificate without MtlsStaticCertificateBindings),
		// the session certificate gets auto-updated with the current cert hash.
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.Certificate = clientCertID1 // Will be auto-updated to cert2's hash
		})

		assert.NotEmpty(t, key, "Should create key with certificate binding")

		// Request will fail because client2 is invalid and is being used to access the api
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client2,
			Path:    "/combined-mtls",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusUnauthorized, // Passes in legacy mode
		})
	})

	t.Run("Fail: non-allowlisted cert even with token binding", func(t *testing.T) {
		// Create session with certificate 3 hash bound to token
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.Certificate = clientCertID3 // Token bound to cert3
		})

		assert.NotEmpty(t, key, "Should create key with certificate binding")

		// Request with cert3 (NOT in allowlist) should fail static mTLS check
		client3 := GetTLSClient(&clientCert3, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client3,
			Path:      "/combined-mtls",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: "not allowed",
		})
	})

	t.Run("Fail: no client certificate provided", func(t *testing.T) {
		// Create session with certificate 1 hash bound to token
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.Certificate = clientCertID1
		})

		assert.NotEmpty(t, key, "Should create key with certificate binding")

		// Request without any client certificate should fail
		clientNoCert := GetTLSClient(nil, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    clientNoCert,
			Path:      "/combined-mtls",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: "Client TLS certificate is required",
		})
	})

	t.Run("Fail: invalid auth token with valid cert", func(t *testing.T) {
		// Request with valid cert but invalid token
		// should the token still be validated if the cert is passed
		// disable insecure
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client1,
			Path:      "/combined-mtls",
			Headers:   map[string]string{"Authorization": "invalid-token"},
			Code:      http.StatusForbidden,
			BodyMatch: MsgApiAccessDisallowed,
		})
	})

	t.Run("Success: static binding with MtlsStaticCertificateBindings", func(t *testing.T) {
		// Create session with static certificate binding (MtlsStaticCertificateBindings)
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.MtlsStaticCertificateBindings = []string{certHash1} // Static binding
		})

		assert.NotEmpty(t, key, "Should create key with static certificate binding")

		// Request with cert1 (in allowlist and statically bound to token) should succeed
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/combined-mtls",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})

	t.Run("Fail: static binding mismatch", func(t *testing.T) {
		// Create session with static binding to cert3
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"combined-mtls-api": {
				APIID: "combined-mtls-api",
			}}
			s.MtlsStaticCertificateBindings = []string{certHash3} // Bound to cert3
		})

		assert.NotEmpty(t, key, "Should create key with static certificate binding")

		// Request with cert1 (in allowlist but not statically bound) should fail
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client1,
			Path:      "/combined-mtls",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusUnauthorized,
			BodyMatch: MsgApiAccessDisallowed,
		})
	})

	t.Run("Dynamic mTLS only (no static binding)", func(t *testing.T) {
		// Create API with only dynamic mTLS (no static mTLS)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "dynamic-mtls-only"
			spec.OrgID = "default"
			// NO static mTLS
			spec.UseMutualTLSAuth = false
			// Enable dynamic mTLS (token-certificate binding)
			spec.UseStandardAuth = true
			spec.UseKeylessAccess = false
			authConf := apidef.AuthConfig{
				Name:           "authToken",
				UseCertificate: true, // This enables dynamic mTLS
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf
			spec.Proxy.ListenPath = "/dynamic-only"
		})

		// Create session with certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"dynamic-mtls-only": {
				APIID: "dynamic-mtls-only",
			}}
			s.Certificate = clientCertID1
		})

		t.Run("valid certificate provided", func(t *testing.T) {
			validCertClient := GetTLSClient(&clientCert1, serverCertPem)
			_, _ = ts.Run(t, test.TestCase{
				Domain:  "localhost",
				Client:  validCertClient,
				Path:    "/dynamic-only",
				Headers: map[string]string{"Authorization": key},
				Code:    http.StatusOK,
			})
		})

		t.Run("different certificate auto-updates session in legacy mode", func(t *testing.T) {
			// should fail, certificate is invalid
			wrongCertClient := GetTLSClient(&clientCert2, serverCertPem)
			_, _ = ts.Run(t, test.TestCase{
				Domain:  "localhost",
				Client:  wrongCertClient,
				Path:    "/dynamic-only",
				Headers: map[string]string{"Authorization": key},
				Code:    http.StatusUnauthorized, // Legacy mode allows any valid cert
			})
		})
	})

	t.Run("Static mTLS only (no dynamic binding)", func(t *testing.T) {
		// Create API with only static mTLS
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "static-mtls-only"
			spec.OrgID = "default"
			// Enable static mTLS with allowlist
			spec.UseMutualTLSAuth = true
			spec.ClientCertificates = []string{clientCertID1, clientCertID2}
			// Standard auth but NO certificate binding
			spec.UseStandardAuth = true
			spec.UseKeylessAccess = false
			authConf := apidef.AuthConfig{
				Name:           "authToken",
				UseCertificate: false, // NO dynamic mTLS
				AuthHeaderName: "Authorization",
			}
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				"authToken": authConf,
			}
			spec.Auth = authConf
			spec.Proxy.ListenPath = "/static-only"
		})

		// Create session without certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"static-mtls-only": {
				APIID: "static-mtls-only",
			}}
		})

		t.Run("allowlisted certificate succeeds", func(t *testing.T) {
			validCertClient := GetTLSClient(&clientCert1, serverCertPem)
			_, _ = ts.Run(t, test.TestCase{
				Domain:  "localhost",
				Client:  validCertClient,
				Path:    "/static-only",
				Headers: map[string]string{"Authorization": key},
				Code:    http.StatusOK,
			})
		})

		t.Run("non-allowlisted certificate fails", func(t *testing.T) {
			invalidCertClient := GetTLSClient(&clientCert3, serverCertPem)
			_, _ = ts.Run(t, test.TestCase{
				Domain:    "localhost",
				Client:    invalidCertClient,
				Path:      "/static-only",
				Headers:   map[string]string{"Authorization": key},
				Code:      http.StatusForbidden,
				BodyMatch: "not allowed",
			})
		})
	})
}

// TestCertificateCheckMW_StrictAllowlistValidation tests that the CertificateCheckMW
// strictly validates against the static allowlist without any fallback to token binding.
// Certificates not in the allowlist will fail regardless of token binding.
func TestCertificateCheckMW_StrictAllowlistValidation(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.AllowUnsafeDynamicMTLSToken = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create client certificates
	// Cert 1: Will be in allowlist
	clientCertPem1, _, _, clientCert1 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID1, err := ts.Gw.CertificateManager.Add(clientCertPem1, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID1, "default")

	// Cert 2: Will NOT be in allowlist but will be bound to token
	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID2, err := ts.Gw.CertificateManager.Add(clientCertPem2, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID2, "default")
	certHash2 := "default" + certs.HexSHA256(clientCert2.Certificate[0])

	// Create API with static mTLS that only allows cert1
	// Cert2 is NOT in the allowlist and will be rejected by CertificateCheckMW
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "strict-allowlist-api"
		spec.OrgID = "default"
		// Enable static mTLS with allowlist containing only cert1
		spec.UseMutualTLSAuth = true
		spec.ClientCertificates = []string{clientCertID1} // Only cert1 in allowlist
		// Enable dynamic mTLS for token binding
		spec.UseStandardAuth = true
		spec.UseKeylessAccess = false
		authConf := apidef.AuthConfig{
			Name:           "authToken",
			UseCertificate: true,
			AuthHeaderName: "Authorization",
		}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": authConf,
		}
		spec.Auth = authConf
		spec.Proxy.ListenPath = "/strict-allowlist"
	})

	t.Run("Certificate not in allowlist fails regardless of token binding", func(t *testing.T) {
		// Create session with cert2 bound via MtlsStaticCertificateBindings
		// Cert2 is NOT in the static allowlist, so it should fail at CertificateCheckMW
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"strict-allowlist-api": {
				APIID: "strict-allowlist-api",
			}}
			s.MtlsStaticCertificateBindings = []string{certHash2} // Static binding to cert2
		})

		assert.NotEmpty(t, key, "Should create key with static certificate binding")

		// Request with cert2 (NOT in allowlist) should fail at CertificateCheckMW
		// Token binding does not bypass the static allowlist validation
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client2,
			Path:      "/strict-allowlist",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: "not allowed",
		})
	})

	t.Run("Allowlisted certificate still works", func(t *testing.T) {
		// Create session with cert1 (which is in the allowlist)
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"strict-allowlist-api": {
				APIID: "strict-allowlist-api",
			}}
			s.Certificate = clientCertID1
		})

		assert.NotEmpty(t, key, "Should create key")

		// Request with cert1 (in allowlist) should succeed via normal path
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/strict-allowlist",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})

	t.Run("Unbound certificate fails", func(t *testing.T) {
		// Create session without any certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"strict-allowlist-api": {
				APIID: "strict-allowlist-api",
			}}
			// No certificate binding
		})

		assert.NotEmpty(t, key, "Should create key")

		// Request with cert2 (NOT in allowlist and NOT bound) should fail
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client2,
			Path:      "/strict-allowlist",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: "not allowed",
		})
	})

	t.Run("No auth token fails validateCertificateFromToken", func(t *testing.T) {
		// Request with cert2 (NOT in allowlist) and no auth token should fail
		// This tests the path where validateCertificateFromToken returns false due to missing token
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client2,
			Path:      "/strict-allowlist",
			Code:      http.StatusForbidden,
			BodyMatch: "not allowed",
		})
	})

	t.Run("Invalid auth token fails validateCertificateFromToken", func(t *testing.T) {
		// Request with cert2 (NOT in allowlist) and invalid auth token should fail
		// This tests the path where validateCertificateFromToken returns false due to invalid token
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client2,
			Path:      "/strict-allowlist",
			Headers:   map[string]string{"Authorization": "invalid-token"},
			Code:      http.StatusForbidden,
			BodyMatch: "not allowed",
		})
	})
}

// TestStaticAndDynamicMTLS_ExpiredCertificate tests expired certificate handling
// Note: The certificate manager rejects expired certificates on Add, so we test
// the expiry check that happens at runtime in the AuthKey middleware
func TestStaticAndDynamicMTLS_ExpiredCertificate(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.AllowUnsafeDynamicMTLSToken = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create a valid client certificate for the allowlist
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID, err := ts.Gw.CertificateManager.Add(clientCertPem, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID, "default")

	// Create API with dynamic mTLS only (to test the AuthKey expiry check)
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "expired-cert-test"
		spec.OrgID = "default"
		// NO static mTLS allowlist - we want to test the AuthKey middleware expiry check
		spec.UseMutualTLSAuth = false
		spec.UseStandardAuth = true
		spec.UseKeylessAccess = false
		authConf := apidef.AuthConfig{
			Name:           "authToken",
			UseCertificate: true,
			AuthHeaderName: "Authorization",
		}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": authConf,
		}
		spec.Auth = authConf
		spec.Proxy.ListenPath = "/expired-test"
	})

	t.Run("Expired certificate fails in AuthKey middleware", func(t *testing.T) {
		// Create session with valid certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"expired-cert-test": {
				APIID: "expired-cert-test",
			}}
			s.Certificate = clientCertID
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Create an expired certificate (not added to cert manager, just used for TLS)
		_, _, _, expiredClientCert := certs.GenCertificate(&x509.Certificate{
			NotBefore: time.Now().AddDate(-1, 0, 0),
			NotAfter:  time.Now().AddDate(0, 0, -1),
		}, false)

		expiredCertClient := GetTLSClient(&expiredClientCert, serverCertPem)

		// Should fail due to expired certificate check in AuthKey middleware
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    expiredCertClient,
			Path:      "/expired-test",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: MsgCertificateExpired,
		})
	})

	t.Run("Valid certificate succeeds", func(t *testing.T) {
		// Create session with valid certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"expired-cert-test": {
				APIID: "expired-cert-test",
			}}
			s.Certificate = clientCertID
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		validCertClient := GetTLSClient(&clientCert, serverCertPem)

		// Should succeed with valid certificate
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  validCertClient,
			Path:    "/expired-test",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})
}

// TestDynamicMTLS_InvalidCertificateInSession tests validateLegacyWithoutCert
// when the session has a certificate ID that doesn't exist in the cert manager
func TestDynamicMTLS_InvalidCertificateInSession(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.AllowUnsafeDynamicMTLSToken = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create API with dynamic mTLS only (no static mTLS)
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "dynamic-mtls-invalid-cert"
		spec.OrgID = "default"
		// NO static mTLS - so CertificateCheckMW won't block requests without certs
		spec.UseMutualTLSAuth = false
		// Enable dynamic mTLS (token-certificate binding)
		spec.UseStandardAuth = true
		spec.UseKeylessAccess = false
		authConf := apidef.AuthConfig{
			Name:           "authToken",
			UseCertificate: true, // This enables dynamic mTLS
			AuthHeaderName: "Authorization",
		}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": authConf,
		}
		spec.Auth = authConf
		spec.Proxy.ListenPath = "/dynamic-invalid-cert"
	})

	t.Run("Session with non-existent certificate fails when no TLS cert provided", func(t *testing.T) {
		// Create session with a certificate ID that doesn't exist in cert manager
		// This simulates corrupted data or a cert that was deleted
		nonExistentCertID := "nonexistent-cert-id"
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"dynamic-mtls-invalid-cert": {
				APIID: "dynamic-mtls-invalid-cert",
			}}
			s.Certificate = nonExistentCertID // Reference to non-existent cert
		})

		assert.NotEmpty(t, key, "Should create key with certificate reference")

		// Request WITHOUT a TLS client certificate
		// This triggers validateLegacyWithoutCert which checks if session.Certificate exists in cert manager
		clientNoCert := GetTLSClient(nil, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    clientNoCert,
			Path:      "/dynamic-invalid-cert",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: MsgApiAccessDisallowed, // ErrAuthCertNotFound maps to this message
		})
	})

	t.Run("Session with empty certificate succeeds when no TLS cert provided", func(t *testing.T) {
		// Create session without any certificate binding
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"dynamic-mtls-invalid-cert": {
				APIID: "dynamic-mtls-invalid-cert",
			}}
			// Leave Certificate empty
		})

		assert.NotEmpty(t, key, "Should create key without certificate")

		// Request WITHOUT a TLS client certificate should succeed
		// validateLegacyWithoutCert returns OK when session.Certificate is empty
		clientNoCert := GetTLSClient(nil, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  clientNoCert,
			Path:    "/dynamic-invalid-cert",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})
}

// TestMultipleCertificateBindings tests scenarios with multiple certificates bound to a token
func TestMultipleCertificateBindings(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.AllowUnsafeDynamicMTLSToken = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create two client certificates
	clientCertPem1, _, _, clientCert1 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID1, err := ts.Gw.CertificateManager.Add(clientCertPem1, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID1, "default")
	certHash1 := "default" + certs.HexSHA256(clientCert1.Certificate[0])

	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID2, err := ts.Gw.CertificateManager.Add(clientCertPem2, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID2, "default")
	certHash2 := "default" + certs.HexSHA256(clientCert2.Certificate[0])

	// Create API with both certs in allowlist
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "multi-binding-api"
		spec.OrgID = "default"
		spec.UseMutualTLSAuth = true
		spec.ClientCertificates = []string{clientCertID1, clientCertID2}
		spec.UseStandardAuth = true
		spec.UseKeylessAccess = false
		authConf := apidef.AuthConfig{
			Name:           "authToken",
			UseCertificate: true,
			AuthHeaderName: "Authorization",
		}
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": authConf,
		}
		spec.Auth = authConf
		spec.Proxy.ListenPath = "/multi-binding"
	})

	t.Run("Token with multiple static bindings", func(t *testing.T) {
		// Create session with multiple certificate bindings
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"multi-binding-api": {
				APIID: "multi-binding-api",
			}}
			s.Certificate = certHash1
			// Bind multiple certificates to the same token
			s.MtlsStaticCertificateBindings = []string{certHash1, certHash2}
		})

		key2 := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"multi-binding-api": {
				APIID: "multi-binding-api",
			}}
			s.Certificate = certHash2
			s.MtlsStaticCertificateBindings = []string{certHash2, certHash1}
		})

		assert.NotEmpty(t, key, "Should create key with multiple certificate bindings")

		// Both certificates should work
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/multi-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})

		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client2,
			Path:    "/multi-binding",
			Headers: map[string]string{"Authorization": key2},
			Code:    http.StatusOK,
		})
	})
}
