// +build go1.13

package gateway

import (
	"crypto/tls"

	//	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestProxyTransport_tlsv3(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	}))
	defer upstream.Close()

	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

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
			spec.Proxy.Transport.ProxyURL = proxy.URL
		})

		client := GetTLSClient(nil, nil)
		client.Transport = &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		}
		ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
	})
}
