//go:build go1.10
// +build go1.10

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/TykTechnologies/tyk/config"

	//	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/test"
)

func (gw *Gateway) uploadCertPublicKey(serverCert tls.Certificate) (string, error) {
	x509Cert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	pubDer, _ := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	pubID, _ := gw.CertificateManager.Add(pubPem, "")

	if pubID != certs.HexSHA256(pubDer) {
		errStr := fmt.Sprintf("certmanager returned wrong pub key fingerprint: %s %s", certs.HexSHA256(pubDer), pubID)
		return "", errors.New(errStr)
	}

	return pubID, nil
}

var (
	handlerEmpty http.HandlerFunc = func(http.ResponseWriter, *http.Request) {}
	handlerEcho                   = func(message string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(message))
		}
	}
)

func newUpstreamSSL(t *testing.T, gw *Gateway, serverCert tls.Certificate, handler http.HandlerFunc) (*httptest.Server, string, func()) {
	pubID, err := gw.uploadCertPublicKey(serverCert)
	if err != nil {
		t.Error(err)
	}

	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{serverCert},
		MaxVersion:         tls.VersionTLS12,
	}

	upstream.StartTLS()
	return upstream, pubID, func() {
		upstream.Close()
		gw.CertificateManager.Delete(pubID, "")
	}
}

func TestPublicKeyPinning(t *testing.T) {
	_, _, _, serverCert := certs.GenServerCertificate()

	t.Run("Pub key match", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			// For host using pinning, it should ignore standard verification in all cases, e.g setting variable below does nothing
			globalConf.ProxySSLInsecureSkipVerify = false
		})
		defer ts.Close()

		upstream, pubID, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": pubID}
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 200})
	})

	t.Run("Pub key not match", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5260

		ts := StartTest(nil)
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": "wrong"}
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("pinning disabled", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			// For host using pinning, it should ignore standard verification in all cases, e.g setting variable below does nothing
			globalConf.ProxySSLInsecureSkipVerify = false
		})
		defer ts.Close()

		upstream, pubID, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CertificatePinningDisabled = true
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": pubID}
			spec.Proxy.TargetURL = upstream.URL
		})

		_, _ = ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Global setting", func(t *testing.T) {
		test.Flaky(t) // TODO: TT-5260

		ts := StartTest(func(globalConf *config.Config) {
			globalConf.Security.PinnedPublicKeys = map[string]string{"127.0.0.1": "wrong"}
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Though proxy", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = true
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		_, _, _, proxyCert := certs.GenServerCertificate()
		proxy := initProxy("https", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
			MaxVersion:   tls.VersionTLS12,
		})

		defer func() {
			proxyErr := proxy.Stop(ts)
			if proxyErr != nil {
				t.Errorf("Cannot stop proxy: %v", proxyErr.Error())
			}
		}()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.ProxyURL = proxy.URL
			spec.PinnedPublicKeys = map[string]string{"*": "wrong"}
		})

		ts.Run(t, test.TestCase{Code: 500})
	})

	t.Run("Enable Common Name check", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.SSLForceCommonNameCheck = true
			globalConf.ProxySSLInsecureSkipVerify = true
		})
		defer ts.Close()

		// start upstream server
		_, _, _, serverCert := certs.GenCertificate(&x509.Certificate{
			EmailAddresses: []string{"test@test.com"},
			Subject:        pkix.Name{CommonName: "localhost"},
		}, false)

		upstream, serverPubID, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		// start proxy
		_, _, _, proxyCert := certs.GenCertificate(&x509.Certificate{
			Subject: pkix.Name{CommonName: "local1.host"},
		}, false)
		proxyPubID, err := ts.Gw.uploadCertPublicKey(proxyCert)
		if err != nil {
			t.Error(err)
		}

		proxy := initProxy("http", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
			MaxVersion:   tls.VersionTLS12,
		})

		defer func() {
			proxyErr := proxy.Stop(ts)
			if proxyErr != nil {
				t.Errorf("Cannot stop proxy: %v", proxyErr.Error())
			}
		}()

		pubKeys := fmt.Sprintf("%s,%s", serverPubID, proxyPubID)
		upstream.URL = strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
		proxy.URL = strings.Replace(proxy.URL, "127.0.0.1", "local1.host", 1)

		ts.Gw.BuildAndLoadAPI([]func(spec *APISpec){func(spec *APISpec) {
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

func TestProxyTransport(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	upstream := httptest.NewUnstartedServer(handlerEcho("test"))
	upstream.TLS = &tls.Config{
		MaxVersion: tls.VersionTLS12,
	}
	upstream.StartTLS()

	defer upstream.Close()

	defer ts.ResetTestConfig()

	//matching ciphers
	t.Run("Global: Cipher match", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		ts.Gw.SetConfig(globalConf)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})
		ts.Run(t, test.TestCase{Path: "/", Code: 200})
	})

	t.Run("Global: Cipher not match", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_RC4_128_SHA"}
		ts.Gw.SetConfig(globalConf)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})
		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Cipher override", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLCipherSuites = []string{"TLS_RSA_WITH_RC4_128_SHA"}
		ts.Gw.SetConfig(globalConf)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 200})
	})

	t.Run("API: MinTLS not match", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 772
		ts.Gw.SetConfig(globalConf)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Invalid proxy", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 771
		ts.Gw.SetConfig(globalConf)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
			// Invalid proxy
			spec.Proxy.Transport.ProxyURL = upstream.URL
		})

		ts.Run(t, test.TestCase{Path: "/", Code: 500})
	})

	t.Run("API: Valid proxy", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		// force creating new transport on each reque
		globalConf.MaxConnTime = -1

		globalConf.ProxySSLMinVersion = 771
		ts.Gw.SetConfig(globalConf)

		_, _, _, proxyCert := certs.GenServerCertificate()
		proxy := initProxy("https", &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
			MaxVersion:   tls.VersionTLS12,
		})
		defer func() {
			proxyErr := proxy.Stop(ts)
			if proxyErr != nil {
				t.Errorf("Cannot stop proxy: %v", proxyErr.Error())
			}
		}()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.Transport.SSLCipherSuites = []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}
			spec.Proxy.Transport.ProxyURL = proxy.URL
		})

		client := GetTLSClient(nil, nil)
		client.Transport = &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		}
		ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
	})
}
