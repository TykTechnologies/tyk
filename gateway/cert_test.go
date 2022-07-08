package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

const (
	internalTLSErr  = "tls: unrecognized name"
	badcertErr      = "tls: bad certificate"
	certNotMatchErr = "Client TLS certificate is required"
)

func TestGatewayTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem, combinedPEM, _ := certs.GenServerCertificate()

	dir, _ := ioutil.TempDir("", "certs")
	defer os.RemoveAll(dir)

	client := GetTLSClient(nil, nil)

	t.Run("Without certificates", func(t *testing.T) {

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
		}
		ts := StartTest(conf)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr, Client: client})
	})

	t.Run("Legacy TLS certificate path", func(t *testing.T) {

		certFilePath := filepath.Join(dir, "server.crt")
		err := ioutil.WriteFile(certFilePath, serverCertPem, 0666)
		if err != nil {
			t.Error("writing serverCertPem")
		}

		certKeyPath := filepath.Join(dir, "server.key")
		err = ioutil.WriteFile(certKeyPath, serverPrivPem, 0666)
		if err != nil {
			t.Error("writing serverPrivPem")
		}

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.HttpServerOptions.Certificates = []config.CertData{{
				Name:     "localhost",
				CertFile: certFilePath,
				KeyFile:  certKeyPath,
			}}
		}

		ts := StartTest(conf)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: client})

		ts.Gw.CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})

	t.Run("File certificate path", func(t *testing.T) {
		certPath := filepath.Join(dir, "server.pem")
		err := ioutil.WriteFile(certPath, combinedPEM, 0666)
		if err != nil {
			t.Error("could not write server.pem file")
		}

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.SSLCertificates = []string{certPath}
			globalConf.HttpServerOptions.UseSSL = true
		}

		ts := StartTest(conf)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: client})

		ts.Gw.CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})

	t.Run("Redis certificate", func(t *testing.T) {
		s := StartTest(nil)
		defer s.Close()
		certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.HttpServerOptions.SSLCertificates = []string{certID}
		}
		ts := StartTest(conf)
		defer ts.Close()

		certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		defer ts.Gw.CertificateManager.Delete(certID, "")
		ts.ReloadGatewayProxy()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: client})

		ts.Gw.CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})
}

func TestGatewayControlAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		tlsConfigCache.Flush()
	}()

	clientWithoutCert := GetTLSClient(nil, nil)
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientWithCert := GetTLSClient(&clientCert, serverCertPem)

	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")
	t.Run("Separate domain", func(t *testing.T) {

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.Security.ControlAPIUseMutualTLS = true
			globalConf.ControlAPIHostname = "localhost"
			globalConf.HttpServerOptions.SSLCertificates = []string{certID}
		}
		ts := StartTest(conf)
		defer ts.Close()

		certID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
		defer ts.Gw.CertificateManager.Delete(certID, "")
		ts.ReloadGatewayProxy()

		defer func() {
			ts.Gw.CertificateManager.FlushCache()
			tlsConfigCache.Flush()
			globalConf := ts.Gw.GetConfig()
			globalConf.HttpServerOptions.SSLCertificates = nil
			globalConf.Security.Certificates.ControlAPI = nil
			ts.Gw.SetConfig(globalConf)
		}()

		unknownErr := "x509: certificate signed by unknown authority"

		_, _ = ts.Run(t, []test.TestCase{
			// Should access tyk without client certificates
			{Client: clientWithoutCert},
			// Should raise error for ControlAPI without certificate
			{ControlRequest: true, ErrorMatch: unknownErr},
			// Should raise error for for unknown certificate
			{ControlRequest: true, ErrorMatch: badcertErr, Client: clientWithCert},
		}...)
	})

	t.Run("Separate domain/ control api with valid cert", func(t *testing.T) {

		clientCertID, _, _ := certs.GetCertIDAndChainPEM(clientCertPem, "")
		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.Security.ControlAPIUseMutualTLS = true
			globalConf.ControlAPIHostname = "localhost"
			globalConf.HttpServerOptions.SSLCertificates = []string{certID}
			globalConf.Security.Certificates.ControlAPI = []string{clientCertID}
		}

		ts := StartTest(conf)
		defer ts.Close()

		certID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
		defer ts.Gw.CertificateManager.Delete(certID, "")

		clientCertID, _ = ts.Gw.CertificateManager.Add(clientCertPem, "")
		defer ts.Gw.CertificateManager.Delete(clientCertID, "")
		ts.ReloadGatewayProxy()

		// Should pass request with valid client cert
		_, _ = ts.Run(t, test.TestCase{
			Path: "/tyk/certs", Code: 200, ControlRequest: true, AdminAuth: true, Client: clientWithCert,
		})
	})
}

func TestAPIMutualTLS(t *testing.T) {

	serverCertPem, _, combinedPEM, _ := certs.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.EnableCustomDomains = true
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	}
	ts := StartTest(conf)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
	if err != nil {
		panic(err)
	}
	defer ts.Gw.CertificateManager.Delete(certID, "")
	ts.ReloadGatewayProxy()

	// Initialize client certificates
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{}, false)

	t.Run("SNI and domain per API", func(t *testing.T) {
		t.Run("API without mutual TLS", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
			})

			_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client, Domain: "localhost"})
		})

		t.Run("MutualTLSCertificate not set", func(t *testing.T) {
			client := GetTLSClient(nil, nil)

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
			})

			_, _ = ts.Run(t, test.TestCase{
				ErrorMatch: badcertErr,
				Client:     client,
				Domain:     "localhost",
			})
		})

		t.Run("Client certificate match", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)
			clientCertID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID}
			})

			_, _ = ts.Run(t, test.TestCase{
				Code: 200, Client: client, Domain: "localhost",
			})

			ts.Gw.CertificateManager.Delete(clientCertID, "")
			ts.Gw.CertificateManager.FlushCache()
			tlsConfigCache.Flush()

			client = GetTLSClient(&clientCert, serverCertPem)
			_, _ = ts.Run(t, test.TestCase{
				Client: client, Domain: "localhost", ErrorMatch: badcertErr,
			})
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _, _, _ := certs.GenCertificate(&x509.Certificate{}, false)
			clientCertID2, _ := ts.Gw.CertificateManager.Add(clientCertPem2, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID2, "")

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

			_, _ = ts.Run(t, test.TestCase{
				Client: client, ErrorMatch: badcertErr, Domain: "localhost",
			})
		})
	})

	t.Run("Multiple APIs on same domain", func(t *testing.T) {
		testSameDomain := func(t *testing.T, domain string) {
			clientCertID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				ts.Gw.BuildAndLoadAPI(
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/without_mutual"
						spec.Domain = domain
					},
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/with_mutual"
						spec.UseMutualTLSAuth = true
						spec.ClientCertificates = certs
						spec.Domain = domain
					},
				)
			}

			t.Run("Without certificate", func(t *testing.T) {
				clientWithoutCert := GetTLSClient(nil, nil)

				loadAPIS()

				_, _ = ts.Run(t, []test.TestCase{
					{
						Path:      "/with_mutual",
						Client:    clientWithoutCert,
						Domain:    domain,
						Code:      403,
						BodyMatch: `"error": "` + certNotMatchErr,
					},
					{
						Path:   "/without_mutual",
						Client: clientWithoutCert,
						Domain: domain,
						Code:   200,
					},
				}...)
			})

			t.Run("Client certificate not match", func(t *testing.T) {
				client := GetTLSClient(&clientCert, serverCertPem)

				loadAPIS()

				certNotAllowedErr := `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`

				_, _ = ts.Run(t, test.TestCase{
					Path:      "/with_mutual",
					Client:    client,
					Domain:    domain,
					Code:      403,
					BodyMatch: `"error": "` + certNotAllowedErr,
				})
			})

			t.Run("Client certificate match", func(t *testing.T) {
				loadAPIS(clientCertID)
				client := GetTLSClient(&clientCert, serverCertPem)

				_, _ = ts.Run(t, test.TestCase{
					Path:   "/with_mutual",
					Domain: domain,
					Client: client,
					Code:   200,
				})
			})
		}

		t.Run("Empty domain", func(t *testing.T) {
			testSameDomain(t, "")
		})

		t.Run("Custom domain", func(t *testing.T) {
			testSameDomain(t, "localhost")
		})
	})

	t.Run("Multiple APIs with Mutual TLS on the same domain", func(t *testing.T) {
		testSameDomain := func(t *testing.T, domain string) {
			clientCertID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID, "")

			clientCertID2, _ := ts.Gw.CertificateManager.Add(clientCertPem2, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID2, "")

			loadAPIS := func(certs []string, certs2 []string) {
				ts.Gw.BuildAndLoadAPI(
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/with_mutual"
						spec.UseMutualTLSAuth = true
						spec.ClientCertificates = certs
						spec.Domain = domain
					},
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/with_mutual_2"
						spec.UseMutualTLSAuth = true
						spec.ClientCertificates = certs2
						spec.Domain = domain
					},
				)
			}

			t.Run("Without certificate", func(t *testing.T) {
				clientWithoutCert := GetTLSClient(nil, nil)

				loadAPIS([]string{}, []string{})

				_, _ = ts.Run(t, []test.TestCase{
					{
						Path:       "/with_mutual",
						Client:     clientWithoutCert,
						Domain:     domain,
						ErrorMatch: badcertErr,
					},
					{
						Path:       "/with_mutual_2",
						Client:     clientWithoutCert,
						Domain:     domain,
						ErrorMatch: badcertErr,
					},
				}...)
			})

			t.Run("Client certificate not match", func(t *testing.T) {
				client := GetTLSClient(&clientCert, serverCertPem)

				loadAPIS([]string{}, []string{})

				_, _ = ts.Run(t, test.TestCase{
					Path:       "/with_mutual",
					Client:     client,
					Domain:     domain,
					ErrorMatch: badcertErr,
				})

				_, _ = ts.Run(t, test.TestCase{
					Path:       "/with_mutual_2",
					Client:     client,
					Domain:     domain,
					ErrorMatch: badcertErr,
				})
			})

			t.Run("Client certificate match", func(t *testing.T) {
				loadAPIS([]string{clientCertID}, []string{clientCertID2})
				client := GetTLSClient(&clientCert, serverCertPem)
				client2 := GetTLSClient(&clientCert2, serverCertPem)

				_, _ = ts.Run(t,
					[]test.TestCase{
						{
							Path:   "/with_mutual",
							Domain: domain,
							Client: client,
							Code:   200,
						},
						{
							Path:      "/with_mutual_2",
							Domain:    domain,
							Client:    client,
							Code:      403,
							BodyMatch: `"error": "` + `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`,
						},
						{
							Path:   "/with_mutual_2",
							Domain: domain,
							Client: client2,
							Code:   200,
						},
						{
							Path:      "/with_mutual",
							Domain:    domain,
							Client:    client2,
							Code:      403,
							BodyMatch: `"error": "` + `Certificate with SHA256 ` + certs.HexSHA256(clientCert2.Certificate[0]) + ` not allowed`,
						},
					}...,
				)
			})
		}

		t.Run("Empty domain", func(t *testing.T) {
			testSameDomain(t, "")
		})

		t.Run("Custom domain", func(t *testing.T) {
			testSameDomain(t, "localhost")
		})
	})

	t.Run("Multiple APIs, mutual on custom", func(t *testing.T) {
		testSameDomain := func(t *testing.T, domain string) {
			clientCertID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				ts.Gw.BuildAndLoadAPI(
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/with_mutual"
						spec.UseMutualTLSAuth = true
						spec.ClientCertificates = certs
						spec.Domain = domain
					},
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/without_mutual"
					},
				)
			}

			t.Run("Without certificate", func(t *testing.T) {
				clientWithoutCert := GetTLSClient(nil, nil)

				loadAPIS()

				if domain == "" {
					_, _ = ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    clientWithoutCert,
						Domain:    domain,
						Code:      403,
						BodyMatch: `"error": "` + certNotMatchErr,
					})
				} else {
					_, _ = ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     clientWithoutCert,
						Domain:     domain,
						ErrorMatch: badcertErr,
					})
				}

				_, _ = ts.Run(t, test.TestCase{
					Path:   "/without_mutual",
					Client: clientWithoutCert,
					Code:   200,
				})
			})

			t.Run("Client certificate not match", func(t *testing.T) {
				client := GetTLSClient(&clientCert, serverCertPem)

				loadAPIS()

				if domain == "" {
					certNotAllowedErr := `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`
					_, _ = ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    client,
						Domain:    domain,
						Code:      403,
						BodyMatch: `"error": "` + certNotAllowedErr,
					})
				} else {
					_, _ = ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     client,
						Domain:     domain,
						ErrorMatch: badcertErr,
					})
				}
			})

			t.Run("Client certificate match", func(t *testing.T) {
				loadAPIS(clientCertID)
				client := GetTLSClient(&clientCert, serverCertPem)

				_, _ = ts.Run(t, test.TestCase{
					Path:   "/with_mutual",
					Domain: domain,
					Client: client,
					Code:   200,
				})
			})
		}

		t.Run("Empty domain", func(t *testing.T) {
			testSameDomain(t, "")
		})

		t.Run("Custom domain", func(t *testing.T) {
			testSameDomain(t, "localhost")
		})
	})

	t.Run("Multiple APIs, mutual on empty", func(t *testing.T) {
		testSameDomain := func(t *testing.T, domain string) {
			clientCertID, _ := ts.Gw.CertificateManager.Add(clientCertPem, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				ts.Gw.BuildAndLoadAPI(
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/with_mutual"
						spec.UseMutualTLSAuth = true
						spec.ClientCertificates = certs
					},
					func(spec *APISpec) {
						spec.Proxy.ListenPath = "/without_mutual"
						spec.Domain = domain
					},
				)
			}

			t.Run("Without certificate", func(t *testing.T) {
				clientWithoutCert := GetTLSClient(nil, nil)

				loadAPIS()

				if domain == "" {
					_, _ = ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    clientWithoutCert,
						Code:      403,
						BodyMatch: `"error": "` + certNotMatchErr,
					})
				} else {
					_, _ = ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     clientWithoutCert,
						ErrorMatch: badcertErr,
					})
				}

				_, _ = ts.Run(t, test.TestCase{
					Path:   "/without_mutual",
					Client: clientWithoutCert,
					Domain: domain,
					Code:   200,
				})
			})

			t.Run("Client certificate not match", func(t *testing.T) {
				client := GetTLSClient(&clientCert, serverCertPem)

				loadAPIS()

				if domain == "" {
					certNotAllowedErr := `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`
					_, _ = ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    client,
						Code:      403,
						BodyMatch: `"error": "` + certNotAllowedErr,
					})
				} else {
					_, _ = ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     client,
						ErrorMatch: badcertErr,
					})
				}
			})

			t.Run("Client certificate match", func(t *testing.T) {
				loadAPIS(clientCertID)
				client := GetTLSClient(&clientCert, serverCertPem)

				_, _ = ts.Run(t, test.TestCase{
					Path:   "/with_mutual",
					Client: client,
					Code:   200,
				})
			})
		}

		t.Run("Empty domain", func(t *testing.T) {
			testSameDomain(t, "")
		})

		t.Run("Custom domain", func(t *testing.T) {
			testSameDomain(t, "localhost")
		})
	})
}

func TestUpstreamMutualTLS(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.dialCtxFn = test.LocalDialer()

	_, _, combinedClientPEM, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	// Mutual TLS protected upstream
	pool := x509.NewCertPool()
	upstream.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}

	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)

	t.Run("Without API", func(t *testing.T) {
		client := GetTLSClient(&clientCert, nil)

		if _, err := client.Get(upstream.URL); err == nil {
			t.Error("Should reject without certificate")
		}

		pool.AddCert(clientCert.Leaf)

		if _, err := client.Get(upstream.URL); err != nil {
			t.Error("Should pass with valid certificate")
		}
	})

	t.Run("Upstream API", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		ts.Gw.SetConfig(globalConf)

		clientCertID, _ := ts.Gw.CertificateManager.Add(combinedClientPEM, "")
		defer ts.Gw.CertificateManager.Delete(clientCertID, "")

		pool.AddCert(clientCert.Leaf)

		// Host values should be different for the purpose of the test
		const targetHost = "host1.target"
		const proxyHost = "host2.proxy"

		api := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = fmt.Sprintf("https://%s:%s", targetHost, upstreamURL.Port())
			spec.UpstreamCertificates = map[string]string{
				"*.target:" + upstreamURL.Port(): clientCertID,
			}
		})[0]

		t.Run("PreserveHostHeader=false", func(t *testing.T) {
			api.Proxy.PreserveHostHeader = false
			ts.Gw.LoadAPI(api)

			// Giving a different value to proxy host, it should not interfere upstream certificate matching
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost, Code: http.StatusOK, Client: test.NewClientLocal()})
		})

		t.Run("PreserveHostHeader=true", func(t *testing.T) {
			api.Proxy.PreserveHostHeader = true
			ts.Gw.LoadAPI(api)

			// Giving a different value to proxy host, it should not interfere upstream certificate matching
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost, Code: http.StatusOK, Client: test.NewClientLocal()})
		})

		t.Run("honor UpstreamCertificatesDisabled flag", func(t *testing.T) {
			api.UpstreamCertificatesDisabled = true
			ts.Gw.LoadAPI(api)

			// Giving a different value to proxy host, it should not interfere upstream certificate matching
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost, Code: http.StatusInternalServerError, Client: test.NewClientLocal()})
		})
	})
}

func TestSSLForceCommonName(t *testing.T) {
	test.Flaky(t) // TODO TT-5112
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	// generate certificate Common Name as valid hostname and SAN as non-empty value
	_, _, _, cert := certs.GenCertificate(&x509.Certificate{
		EmailAddresses: []string{"test@test.com"},
		Subject:        pkix.Name{CommonName: "host1.local"},
	}, false)

	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   tls.VersionTLS12,
	}

	upstream.StartTLS()
	defer upstream.Close()

	// test case to ensure that Golang doesn't check against CommonName if SAN is non empty
	t.Run("Force Common Name Check is Disabled", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		targetURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = targetURL
		})
		_, _ = ts.Run(t, test.TestCase{Code: 500, BodyMatch: "There was a problem proxying the request", Client: test.NewClientLocal()})
	})

	t.Run("Force Common Name Check is Enabled", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		globalConf := ts.Gw.GetConfig()
		globalConf.SSLForceCommonNameCheck = true
		ts.Gw.SetConfig(globalConf)

		targetURL := strings.Replace(upstream.URL, "127.0.0.1", "host1.local", 1)
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = targetURL
		})

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: test.NewClientLocal()})
	})
}

func TestKeyWithCertificateTLS(t *testing.T) {
	test.Flaky(t) // TODO TT-5112

	_, _, combinedPEM, _ := certs.GenServerCertificate()
	serverCertID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.EnableCustomDomains = true
		globalConf.HashKeyFunction = ""
		globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
		globalConf.HealthCheckEndpointName = "hello"
	}

	ts := StartTest(conf)
	defer ts.Close()

	serverCertID, _ = ts.Gw.CertificateManager.Add(combinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(serverCertID, "")
	ts.ReloadGatewayProxy()

	orgId := "default"
	t.Run("Without domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.BaseIdentityProvidedBy = apidef.AuthToken
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				apidef.AuthTokenType: {UseCertificate: true},
			}
			spec.Proxy.ListenPath = "/"
			spec.OrgID = orgId
		})

		client := GetTLSClient(&clientCert, nil)

		t.Run("Cert unknown", func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{Code: 403, Client: client})
		})

		t.Run("Cert known", func(t *testing.T) {
			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.AccessRights = map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}}
			})

			if key == "" {
				t.Fatal("Should create key based on certificate")
			}

			_, key = ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.AccessRights = map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}}
			})

			if key != "" {
				t.Fatal("Should not allow create key based on the same certificate")
			}
			client := GetTLSClient(&clientCert, nil)

			_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})

			// Domain is not set, but we still pass it, it should still work
			_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Domain: "localhost", Client: client})
		})
	})

	t.Run("With custom domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.BaseIdentityProvidedBy = apidef.AuthToken
				spec.AuthConfigs = map[string]apidef.AuthConfig{
					apidef.AuthTokenType: {UseCertificate: true},
				}
				spec.Proxy.ListenPath = "/test1"
				spec.OrgID = orgId
				spec.Domain = "localhost"
			},
			func(spec *APISpec) {
				spec.Proxy.ListenPath = "/test2"
				spec.OrgID = orgId
			},
		)

		client := GetTLSClient(&clientCert, nil)

		t.Run("Cert unknown", func(t *testing.T) {
			_, _ = ts.Run(t,
				test.TestCase{Code: 404, Path: "/test1", Client: client},
				test.TestCase{Code: 403, Path: "/test1", Domain: "localhost", Client: client},
			)
		})

		t.Run("Cert known", func(t *testing.T) {
			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.AccessRights = map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}}
			})

			if key == "" {
				t.Fatal("Should create key based on certificate")
			}

			_, secondKey := ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.AccessRights = map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}}
			})

			if secondKey != "" {
				t.Fatal("Should not allow create key based on the same certificate")
			}

			_, _ = ts.Run(t, test.TestCase{Path: "/test1", Code: 404, Client: client})

			// Domain is not set, but we still pass it, it should still work
			_, _ = ts.Run(t, test.TestCase{Path: "/test1", Code: 200, Domain: "localhost", Client: client})

			// key should also work without cert
			header := map[string]string{
				headers.Authorization: key,
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			_, _ = ts.Run(t, test.TestCase{Path: "/test1", Headers: header, Code: http.StatusOK, Domain: "localhost", Client: client})
		})
	})

	t.Run("With regex custom domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		api := ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.APIID = "api-with-regex-custom-domain"
				spec.UseKeylessAccess = false
				spec.BaseIdentityProvidedBy = apidef.AuthToken
				spec.AuthConfigs = map[string]apidef.AuthConfig{
					apidef.AuthTokenType: {UseCertificate: true},
				}
				spec.Proxy.ListenPath = "/test1"
				spec.OrgID = orgId
				spec.Domain = "{?:host1|host2}" // gorilla type regex
			},
		)[0]

		client := GetTLSClient(&clientCert, nil)
		client.Transport = test.NewTransport(test.WithLocalDialer())

		_, _ = ts.Run(t, []test.TestCase{
			{Code: http.StatusNotFound, Path: "/test1", Client: client},
			{Code: http.StatusForbidden, Path: "/test1", Domain: "host1", Client: client},
			{Code: http.StatusForbidden, Path: "/test1", Domain: "host2", Client: client},
		}...)

		_, _ = ts.CreateSession(func(s *user.SessionState) {
			s.Certificate = clientCertID
			s.AccessRights = map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID, Versions: []string{"v1"},
			}}
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Path: "/test1", Domain: "host2", Client: client})
	})

	// check that a key no longer works after the cert is removed
	t.Run("Cert removed", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.BaseIdentityProvidedBy = apidef.AuthToken
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				apidef.AuthTokenType: {UseCertificate: true},
			}
			spec.Proxy.ListenPath = "/"
			spec.OrgID = orgId
		})
		client := GetTLSClient(&clientCert, nil)
		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.Certificate = clientCertID
			s.AccessRights = map[string]user.AccessDefinition{"test": {
				APIID: "test", Versions: []string{"v1"},
			}}
		})

		if key == "" {
			t.Fatal("Should create key based on certificate")
		}

		// check we can use the key after remove the cert
		_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
		ts.Gw.CertificateManager.Delete(clientCertID, orgId)
		// now we should not be allowed to use the key
		_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 403, Client: client})
	})

	// check that key has been updated with wrong certificate
	t.Run("Key has been updated with wrong certificate key", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.BaseIdentityProvidedBy = apidef.AuthToken
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				apidef.AuthTokenType: {UseCertificate: true},
			}
			spec.Proxy.ListenPath = "/"
			spec.OrgID = orgId
		})
		client := GetTLSClient(&clientCert, nil)
		session, key := ts.CreateSession(func(s *user.SessionState) {
			s.Certificate = clientCertID
			s.AccessRights = map[string]user.AccessDefinition{"test": {
				APIID: "test", Versions: []string{"v1"},
			}}
		})

		if key == "" {
			t.Fatal("Should create key based on certificate")
		}

		// check we can use the key after remove the cert
		_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
		session.Certificate = "fooBar"
		// update redis directly since we have protection not to allow create of a session with wrong certificate
		err = ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(clientCertID, ts.Gw.GetConfig().HashKeys), session, 0, ts.Gw.GetConfig().HashKeys)
		if err != nil {
			t.Error("could not update session in Session Manager. " + err.Error())
		}

		// key should also work without cert
		header := map[string]string{
			headers.Authorization: key,
		}
		newClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		_, _ = ts.Run(t, test.TestCase{Path: "/", Headers: header, Code: http.StatusForbidden, Client: newClient})

		// now we should not be allowed to use the key
		// this call should also migrate the certificate field data
		_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
		updatedSession, _ := ts.Gw.GlobalSessionManager.SessionDetail(session.OrgID, session.KeyID, false)

		if updatedSession.Certificate != clientCertID {
			t.Error("Certificate should be properly updated.")
		}

		_, _ = ts.Run(t, test.TestCase{Path: "/", Headers: header, Code: http.StatusOK, Client: newClient})

	})
}

func TestAPICertificate(t *testing.T) {

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{}
	}

	ts := StartTest(conf)
	defer ts.Close()

	_, _, combinedPEM, _ := certs.GenServerCertificate()
	serverCertID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(serverCertID, "")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}}}

	t.Run("Cert set via API", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Certificates = []string{serverCertID}
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: client})
	})

	t.Run("Cert unknown", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr})
	})
}

func TestCertificateHandlerTLS(t *testing.T) {
	test.Flaky(t) // TODO: TT-5261

	_, _, combinedServerPEM, serverCert := certs.GenCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost", "tyk-gateway"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
		Subject:     pkix.Name{CommonName: "localhost"},
		Issuer:      pkix.Name{CommonName: "localhost"},
	}, true)
	serverCertID := certs.HexSHA256(serverCert.Certificate[0])
	clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{
		DNSNames: []string{"localhost"},
		Subject:  pkix.Name{CommonName: "localhost"},
		Issuer:   pkix.Name{CommonName: "localhost"},
	}, true)
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("List certificates, empty", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Path: "/tyk/certs?org_id=1", Code: 200, AdminAuth: true, BodyMatch: `{"certs":null}`,
		})
	})

	t.Run("Should add certificates with and without private keys", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			// Public Certificate
			{Method: "POST", Path: "/tyk/certs?org_id=1", Data: string(clientPEM), AdminAuth: true, Code: 200, BodyMatch: `"id":"1` + clientCertID},
			// Public + Private
			{Method: "POST", Path: "/tyk/certs?org_id=1", Data: string(combinedServerPEM), AdminAuth: true, Code: 200, BodyMatch: `"id":"1` + serverCertID},
		}...)
	})

	t.Run("List certificates, non empty", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertID},
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: serverCertID},
		}...)
	})

	t.Run("List certificates, detailed mode", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodGet, Path: "/tyk/certs?org_id=1&mode=detailed", AdminAuth: true, Code: http.StatusOK, BodyMatchFunc: func(data []byte) bool {
				expectedAPICertBasics := APIAllCertificateBasics{
					Certs: []*certs.CertificateBasics{
						{
							ID:            "1" + clientCertID,
							IssuerCN:      clientCert.Leaf.Issuer.CommonName,
							SubjectCN:     clientCert.Leaf.Subject.CommonName,
							DNSNames:      clientCert.Leaf.DNSNames,
							HasPrivateKey: false,
							NotAfter:      clientCert.Leaf.NotAfter.UTC().Truncate(time.Second),
							NotBefore:     clientCert.Leaf.NotBefore.UTC().Truncate(time.Second),
						},
						{
							ID:            "1" + serverCertID,
							IssuerCN:      serverCert.Leaf.Issuer.CommonName,
							SubjectCN:     serverCert.Leaf.Subject.CommonName,
							DNSNames:      serverCert.Leaf.DNSNames,
							HasPrivateKey: true,
							NotAfter:      serverCert.Leaf.NotAfter.UTC().Truncate(time.Second),
							NotBefore:     serverCert.Leaf.NotBefore.UTC().Truncate(time.Second),
						},
					},
				}
				apiAllCertificateBasics := APIAllCertificateBasics{}
				_ = json.Unmarshal(data, &apiAllCertificateBasics)
				assert.Equal(t, expectedAPICertBasics, apiAllCertificateBasics)
				return true
			}},
		}...)
	})

	certMetaTemplate := `{"id":"1%s","fingerprint":"%s","has_private":%s`

	t.Run("Certificate meta info", func(t *testing.T) {
		clientCertMeta := fmt.Sprintf(certMetaTemplate, clientCertID, clientCertID, "false")
		serverCertMeta := fmt.Sprintf(certMetaTemplate, serverCertID, serverCertID, "true")

		_, _ = ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/certs/1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: serverCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `\[` + serverCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertMeta},
		}...)
	})

	t.Run("Certificate removal", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Method: "DELETE", Path: "/tyk/certs/1" + serverCertID + "?org_id=1", AdminAuth: true, Code: 200},
			{Method: "DELETE", Path: "/tyk/certs/1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `{"certs":null}`},
		}...)
	})
}

func TestCipherSuites(t *testing.T) {

	//configure server so we can useSSL and utilize the logic, but skip verification in the clients
	_, _, combinedPEM, _ := certs.GenServerCertificate()
	serverCertID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.Ciphers = []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"}
		globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
	}
	ts := StartTest(conf)
	defer ts.Close()

	serverCertID, _ = ts.Gw.CertificateManager.Add(combinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(serverCertID, "")
	ts.ReloadGatewayProxy()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	//matching ciphers
	t.Run("Cipher match", func(t *testing.T) {

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			CipherSuites:       getCipherAliases([]string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"}),
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}}}

		// If there is an internal TLS error it will fail test
		_, _ = ts.Run(t, test.TestCase{Client: client, Path: "/"})
	})

	t.Run("Cipher non-match", func(t *testing.T) {

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			CipherSuites:       getCipherAliases([]string{"TLS_RSA_WITH_AES_256_CBC_SHA"}), // not matching ciphers
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}}}

		_, _ = ts.Run(t, test.TestCase{Client: client, Path: "/", ErrorMatch: "tls: handshake failure"})
	})
}
