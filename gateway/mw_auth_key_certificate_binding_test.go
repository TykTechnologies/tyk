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

// TestCertificateTokenBinding tests the certificate-token binding feature for static mTLS
func TestCertificateTokenBinding(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		// Enable certificate binding
		globalConf.Security.EnableCertificateBinding = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create two different client certificates
	clientCertPem1, _, _, clientCert1 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID1, err := ts.Gw.CertificateManager.Add(clientCertPem1, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID1, "default")
	// Compute the certificate hash (OrgID + SHA256) that the code will use
	certHash1 := "default" + certs.HexSHA256(clientCert1.Certificate[0])

	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID2, err := ts.Gw.CertificateManager.Add(clientCertPem2, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID2, "default")
	_ = "default" + certs.HexSHA256(clientCert2.Certificate[0]) // certHash2 used in test below

	// Create API with static mTLS
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-api"
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
		spec.Proxy.ListenPath = "/cert-binding"
		spec.OrgID = "default"
	})

	t.Run("Token bound to certificate - success with correct cert", func(t *testing.T) {
		// First request without token should auto-bind the certificate to a new session
		client1 := GetTLSClient(&clientCert1, serverCertPem)

		// Create a session explicitly and bind cert hash
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			s.Certificate = certHash1
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Request with the correct certificate should succeed
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/cert-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})

	t.Run("Token bound to certificate - fail with different cert", func(t *testing.T) {
		// Create session with certificate 1 hash
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			s.Certificate = certHash1
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Attempt to use the token with a different certificate should fail
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    client2,
			Path:      "/cert-binding",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: MsgApiAccessDisallowed,
		})
	})

	t.Run("Token bound to certificate - fail without certificate", func(t *testing.T) {
		// Create session with certificate 1 hash
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			s.Certificate = certHash1
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Attempt to use the token without any client certificate should fail
		// Use a TLS client that trusts the server but doesn't provide a client cert
		clientNoCert := GetTLSClient(nil, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    clientNoCert,
			Path:      "/cert-binding",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: MsgApiAccessDisallowed,
		})
	})

	t.Run("Certificate binding disabled - token works with any cert", func(t *testing.T) {
		// Temporarily disable certificate binding
		globalConf := ts.Gw.GetConfig()
		globalConf.Security.EnableCertificateBinding = false
		ts.Gw.SetConfig(globalConf)

		// Create session with certificate 1 hash
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			s.Certificate = certHash1
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Token should work with the bound certificate
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/cert-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})

		// Token should also work with a different certificate when binding is disabled
		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client2,
			Path:    "/cert-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})

		// Re-enable certificate binding for other tests
		globalConf.Security.EnableCertificateBinding = true
		ts.Gw.SetConfig(globalConf)
	})

	t.Run("Token without certificate stored - binding not enforced", func(t *testing.T) {
		// Create session without a certificate
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			// Don't set Certificate field
		})

		assert.NotEmpty(t, key, "Should create key without certificate")

		// Token should work with any certificate since no certificate is bound
		client1 := GetTLSClient(&clientCert1, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client1,
			Path:    "/cert-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})

		client2 := GetTLSClient(&clientCert2, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			Domain:  "localhost",
			Client:  client2,
			Path:    "/cert-binding",
			Headers: map[string]string{"Authorization": key},
			Code:    http.StatusOK,
		})
	})
}

// TestCertificateTokenBindingWithExpiredCert tests certificate binding with expired certificates
func TestCertificateTokenBindingWithExpiredCert(t *testing.T) {
	// Setup server certificate
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.Security.ControlAPIUseMutualTLS = false
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
		globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
		globalConf.Security.EnableCertificateBinding = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "default")
	ts.ReloadGatewayProxy()

	// Create valid client certificate
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertID, err := ts.Gw.CertificateManager.Add(clientCertPem, "default")
	assert.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(clientCertID, "default")
	certHash := "default" + certs.HexSHA256(clientCert.Certificate[0])

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-api"
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
		spec.Proxy.ListenPath = "/cert-binding"
		spec.OrgID = "default"
	})

	t.Run("Expired certificate should fail before binding check", func(t *testing.T) {
		// Create session with valid certificate hash
		key := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{"test-api": {
				APIID: "test-api",
			}}
			s.Certificate = certHash
		})

		assert.NotEmpty(t, key, "Should create key with certificate")

		// Create an expired certificate
		_, _, _, expiredClientCert := certs.GenCertificate(&x509.Certificate{
			NotBefore: time.Now().AddDate(-1, 0, 0),
			NotAfter:  time.Now().AddDate(0, 0, -1),
		}, false)

		expiredCertClient := GetTLSClient(&expiredClientCert, serverCertPem)

		// Should fail due to expired certificate, not binding mismatch
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    expiredCertClient,
			Path:      "/cert-binding",
			Headers:   map[string]string{"Authorization": key},
			Code:      http.StatusForbidden,
			BodyMatch: MsgCertificateExpired,
		})
	})
}
