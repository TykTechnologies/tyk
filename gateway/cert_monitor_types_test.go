package gateway

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestCertificateTypes_Upstream tests upstream certificate monitoring
func TestCertificateTypes_Upstream(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Generate upstream certificate expiring in 20 days (within 30-day warning threshold)
	_, _, upstreamCombinedPEM, _ := certs.GenCertificate(&x509.Certificate{
		Subject: pkix.Name{CommonName: "Upstream Service"},
		NotAfter: time.Now().Add(20 * 24 * time.Hour), // 20 days from now
	}, false)
	certID, err := ts.Gw.CertificateManager.Add(upstreamCombinedPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Gw.CertificateManager.Delete(certID, "")

	// Create API with upstream certificate
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "upstream-test"
		spec.Proxy.ListenPath = "/upstream-test"
		spec.UseKeylessAccess = true
		spec.UpstreamCertificates = map[string]string{
			"*": certID,
		}
	})

	// Make a request to trigger upstream certificate check
	_, _ = ts.Run(t, test.TestCase{
		Path: "/upstream-test",
		Code: 200,
	})

	// Wait for batch processing
	time.Sleep(2 * time.Second)

	t.Log("Upstream certificate check triggered")
}

// TestCertificateTypes_Client tests client certificate monitoring
func TestCertificateTypes_Client(t *testing.T) {
	// Generate server certificate for gateway
	serverCertPEM, _, combinedServerPEM, _ := certs.GenServerCertificate()

	ts := StartTest(func(c *config.Config) {
		c.HttpServerOptions.UseSSL = true
		c.HttpServerOptions.SSLCertificates = []string{"*"}
	})
	defer ts.Close()

	serverCertID, _ := ts.Gw.CertificateManager.Add(combinedServerPEM, "")
	defer ts.Gw.CertificateManager.Delete(serverCertID, "")

	// Generate client certificate expiring in 20 days
	_, _, clientCombinedPEM, clientCert := certs.GenCertificate(&x509.Certificate{
		Subject: pkix.Name{CommonName: "Test Client"},
		NotAfter: time.Now().Add(20 * 24 * time.Hour), // 20 days from now
	}, false)
	clientCertID, _ := ts.Gw.CertificateManager.Add(clientCombinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(clientCertID, "")

	// Create API with client certificate auth
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "client-test"
		spec.Proxy.ListenPath = "/client-test"
		spec.UseMutualTLSAuth = true
		spec.ClientCertificates = []string{clientCertID}
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
	})

	// Create session with client certificate
	ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			"client-test": {
				APIID: "client-test",
			},
		}
		s.Certificate = clientCertID
	})

	// Make a request with client certificate to trigger check
	client := GetTLSClient(&clientCert, serverCertPEM)
	_, _ = ts.Run(t, test.TestCase{
		Client: client,
		Path:   "/client-test",
		Code:   200,
	})

	// Wait for batch processing
	time.Sleep(2 * time.Second)

	t.Log("Client certificate check triggered")
}
