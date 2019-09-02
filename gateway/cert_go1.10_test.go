// +build go1.10

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestPublicKeyPinning(t *testing.T) {
	_, _, _, serverCert := genServerCertificate()
	x509Cert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubID, _ := CertificateManager.Add(pubPem, "")
	defer CertificateManager.Delete(pubID)

	if pubID != certs.HexSHA256(pubDer) {
		t.Error("Certmanager returned wrong pub key fingerprint:", certs.HexSHA256(pubDer), pubID)
	}

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
}

func TestProxyTransport(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	}))
	defer upstream.Close()

	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	//matching ciphers
	t.Run("Global: Cipher match", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		config.SetGlobal(globalConf)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})
		ts.Run(t, test.TestCase{Path: "/", Code: 200})
	})

	t.Run("Global: Cipher not match", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_RC4_128_SHA"}
		config.SetGlobal(globalConf)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})
		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Cipher override", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_RC4_128_SHA"}
		config.SetGlobal(globalConf)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 200})
	})

	t.Run("API: MinTLS not match", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 772
		config.SetGlobal(globalConf)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Invalid proxy", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 771
		config.SetGlobal(globalConf)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
			// Invalid proxy
			spec.Proxy.Transport.ProxyURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Valid proxy", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 771
		config.SetGlobal(globalConf)

		_, _, _, proxyCert := genServerCertificate()
		proxy := initProxy("https", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
		})
		defer proxy.Stop()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
			spec.Proxy.Transport.ProxyURL = proxy.URL
		})

		client := getTLSClient(nil, nil)
		client.Transport = &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		}
		ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
	})
}
