// +build go1.10

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestPublicKeyPinning(t *testing.T) {
	_, _, _, serverCert := genServerCertificate()
	pubID, err := uploadCertPublicKey(serverCert)
	if err != nil {
		t.Error(err)
	}
	defer CertificateManager.Delete(pubID, "")

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	upstream.TLS = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{serverCert},
	}

	upstream.StartTLS()
	defer upstream.Close()

	t.Run("Pub key match", func(t *testing.T) {
		globalConf := config.Global()
		// For host using pinning, it should ignore standard verification in all cases, e.g setting variable below does nothing
		globalConf.ProxySSLInsecureSkipVerify = false
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": pubID}
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 200})
	})

	t.Run("Pub key not match", func(t *testing.T) {
		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": "wrong"}
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Global setting", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.Security.PinnedPublicKeys = map[string]string{"127.0.0.1": "wrong"}
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Though proxy", func(t *testing.T) {
		_, _, _, proxyCert := genServerCertificate()
		proxy := initProxy("https", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
		})

		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		defer proxy.Stop()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.ProxyURL = proxy.URL
			spec.PinnedPublicKeys = map[string]string{"*": "wrong"}
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Enable Common Name check", func(t *testing.T) {
		// start upstream server
		_, _, _, serverCert := genCertificate(&x509.Certificate{
			EmailAddresses: []string{"test@test.com"},
			Subject:        pkix.Name{CommonName: "localhost"},
		})
		serverPubID, err := uploadCertPublicKey(serverCert)
		if err != nil {
			t.Error(err)
		}
		defer CertificateManager.Delete(serverPubID, "")

		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}))
		upstream.TLS = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{serverCert},
		}

		upstream.StartTLS()
		defer upstream.Close()

		// start proxy
		_, _, _, proxyCert := genCertificate(&x509.Certificate{
			Subject: pkix.Name{CommonName: "local1.host"},
		})
		proxyPubID, err := uploadCertPublicKey(proxyCert)
		if err != nil {
			t.Error(err)
		}
		defer CertificateManager.Delete(proxyPubID, "")

		proxy := initProxy("http", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
		})
		defer proxy.Stop()

		globalConf := config.Global()
		globalConf.SSLForceCommonNameCheck = true
		globalConf.ProxySSLInsecureSkipVerify = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		pubKeys := fmt.Sprintf("%s,%s", serverPubID, proxyPubID)
		upstream.URL = strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
		proxy.URL = strings.Replace(proxy.URL, "127.0.0.1", "local1.host", 1)

		BuildAndLoadAPI([]func(spec *APISpec){func(spec *APISpec) {
			spec.Proxy.ListenPath = "/valid"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.ProxyURL = proxy.URL
			spec.PinnedPublicKeys = map[string]string{"*": pubKeys}
		},
			func(spec *APISpec) {
				spec.Proxy.ListenPath = "/invalid"
				spec.Proxy.TargetURL = upstream.URL
				spec.Proxy.Transport.ProxyURL = proxy.URL
				spec.PinnedPublicKeys = map[string]string{"*": "wrong"}
			}}...)

		ts.Run(t, []test.TestCase{
			{Code: 200, Path: "/valid"},
			{Code: 500, Path: "/invalid"},
		}...)
	})
}
