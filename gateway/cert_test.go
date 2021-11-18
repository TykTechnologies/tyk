package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/headers"

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

		ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr, Client: client})
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

		ts.Run(t, test.TestCase{Code: 200, Client: client})

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

		ts.Run(t, test.TestCase{Code: 200, Client: client})

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

		ts.Run(t, test.TestCase{Code: 200, Client: client})

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
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
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

		ts.Run(t, []test.TestCase{
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
		ts.Run(t, test.TestCase{
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
	clientCertPem, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
	clientCertPem2, _, _, clientCert2 := certs.GenCertificate(&x509.Certificate{})

	t.Run("SNI and domain per API", func(t *testing.T) {
		t.Run("API without mutual TLS", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client, Domain: "localhost"})
		})

		t.Run("MutualTLSCertificate not set", func(t *testing.T) {
			client := GetTLSClient(nil, nil)

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
			})

			ts.Run(t, test.TestCase{
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

			ts.Run(t, test.TestCase{
				Code: 200, Client: client, Domain: "localhost",
			})

			ts.Gw.CertificateManager.Delete(clientCertID, "")
			ts.Gw.CertificateManager.FlushCache()
			tlsConfigCache.Flush()

			client = GetTLSClient(&clientCert, serverCertPem)
			ts.Run(t, test.TestCase{
				Client: client, Domain: "localhost", ErrorMatch: badcertErr,
			})
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _, _, _ := certs.GenCertificate(&x509.Certificate{})
			clientCertID2, _ := ts.Gw.CertificateManager.Add(clientCertPem2, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID2, "")

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

			ts.Run(t, test.TestCase{
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

				ts.Run(t, []test.TestCase{
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

				ts.Run(t, test.TestCase{
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

				ts.Run(t, test.TestCase{
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

				ts.Run(t, []test.TestCase{
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

				ts.Run(t, test.TestCase{
					Path:       "/with_mutual",
					Client:     client,
					Domain:     domain,
					ErrorMatch: badcertErr,
				})

				ts.Run(t, test.TestCase{
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

				ts.Run(t,
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
					ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    clientWithoutCert,
						Domain:    domain,
						Code:      403,
						BodyMatch: `"error": "` + certNotMatchErr,
					})
				} else {
					ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     clientWithoutCert,
						Domain:     domain,
						ErrorMatch: badcertErr,
					})
				}

				ts.Run(t, test.TestCase{
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
					ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    client,
						Domain:    domain,
						Code:      403,
						BodyMatch: `"error": "` + certNotAllowedErr,
					})
				} else {
					ts.Run(t, test.TestCase{
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

				ts.Run(t, test.TestCase{
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
					ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    clientWithoutCert,
						Code:      403,
						BodyMatch: `"error": "` + certNotMatchErr,
					})
				} else {
					ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     clientWithoutCert,
						ErrorMatch: badcertErr,
					})
				}

				ts.Run(t, test.TestCase{
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
					ts.Run(t, test.TestCase{
						Path:      "/with_mutual",
						Client:    client,
						Code:      403,
						BodyMatch: `"error": "` + certNotAllowedErr,
					})
				} else {
					ts.Run(t, test.TestCase{
						Path:       "/with_mutual",
						Client:     client,
						ErrorMatch: badcertErr,
					})
				}
			})

			t.Run("Client certificate match", func(t *testing.T) {
				loadAPIS(clientCertID)
				client := GetTLSClient(&clientCert, serverCertPem)

				ts.Run(t, test.TestCase{
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

	_, _, combinedClientPEM, clientCert := certs.GenCertificate(&x509.Certificate{})
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
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost, Code: http.StatusOK})
		})

		t.Run("PreserveHostHeader=true", func(t *testing.T) {
			api.Proxy.PreserveHostHeader = true
			ts.Gw.LoadAPI(api)

			// Giving a different value to proxy host, it should not interfere upstream certificate matching
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost, Code: http.StatusOK})
		})
	})
}

func TestSSLForceCommonName(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	// generate certificate Common Name as valid hostname and SAN as non-empty value
	_, _, _, cert := certs.GenCertificate(&x509.Certificate{
		EmailAddresses: []string{"test@test.com"},
		Subject:        pkix.Name{CommonName: "host1.local"},
	})

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
		ts.Run(t, test.TestCase{Code: 500, BodyMatch: "There was a problem proxying the request"})
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

		ts.Run(t, test.TestCase{Code: 200})
	})
}

func TestKeyWithCertificateTLS(t *testing.T) {
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
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.BaseIdentityProvidedBy = apidef.AuthToken
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				authTokenType: {UseCertificate: true},
			}
			spec.Proxy.ListenPath = "/"
			spec.OrgID = orgId
		})

		client := GetTLSClient(&clientCert, nil)

		t.Run("Cert unknown", func(t *testing.T) {
			ts.Run(t, test.TestCase{Code: 403, Client: client})
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

			ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})

			// Domain is not set, but we still pass it, it should still work
			ts.Run(t, test.TestCase{Path: "/", Code: 200, Domain: "localhost", Client: client})
		})
	})

	t.Run("With custom domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.BaseIdentityProvidedBy = apidef.AuthToken
				spec.AuthConfigs = map[string]apidef.AuthConfig{
					authTokenType: {UseCertificate: true},
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
			ts.Run(t,
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

			ts.Run(t, test.TestCase{Path: "/test1", Code: 404, Client: client})

			// Domain is not set, but we still pass it, it should still work
			ts.Run(t, test.TestCase{Path: "/test1", Code: 200, Domain: "localhost", Client: client})

			// key should also work without cert
			header := map[string]string{
				headers.Authorization: key,
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			ts.Run(t, test.TestCase{Path: "/test1", Headers: header, Code: http.StatusOK, Domain: "localhost", Client: client})
		})
	})

	t.Run("With regex custom domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
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
					authTokenType: {UseCertificate: true},
				}
				spec.Proxy.ListenPath = "/test1"
				spec.OrgID = orgId
				spec.Domain = "{?:host1|host2}" // gorilla type regex
			},
		)[0]

		client := GetTLSClient(&clientCert, nil)

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
		clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
		clientCertID, err := ts.Gw.CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.BaseIdentityProvidedBy = apidef.AuthToken
			spec.AuthConfigs = map[string]apidef.AuthConfig{
				authTokenType: {UseCertificate: true},
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
		ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
		ts.Gw.CertificateManager.Delete(clientCertID, orgId)
		// now we should not be allowed to use the key
		ts.Run(t, test.TestCase{Path: "/", Code: 403, Client: client})
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

		ts.Run(t, test.TestCase{Code: 200, Client: client})
	})

	t.Run("Cert unknown", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr})
	})
}

func TestCertificateHandlerTLS(t *testing.T) {
	_, _, combinedServerPEM, serverCert := certs.GenServerCertificate()
	serverCertID := certs.HexSHA256(serverCert.Certificate[0])

	clientPEM, _, _, clientCert := certs.GenCertificate(&x509.Certificate{})
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])

	ts := StartTest(nil)
	defer ts.Close()

	t.Run("List certificates, empty", func(t *testing.T) {
		ts.Run(t, test.TestCase{
			Path: "/tyk/certs?org_id=1", Code: 200, AdminAuth: true, BodyMatch: `{"certs":null}`,
		})
	})

	t.Run("Should add certificates with and without private keys", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			// Public Certificate
			{Method: "POST", Path: "/tyk/certs?org_id=1", Data: string(clientPEM), AdminAuth: true, Code: 200, BodyMatch: `"id":"1` + clientCertID},
			// Public + Private
			{Method: "POST", Path: "/tyk/certs?org_id=1", Data: string(combinedServerPEM), AdminAuth: true, Code: 200, BodyMatch: `"id":"1` + serverCertID},
		}...)
	})

	t.Run("List certificates, non empty", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertID},
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: serverCertID},
		}...)
	})

	certMetaTemplate := `{"id":"1%s","fingerprint":"%s","has_private":%s`

	t.Run("Certificate meta info", func(t *testing.T) {
		clientCertMeta := fmt.Sprintf(certMetaTemplate, clientCertID, clientCertID, "false")
		serverCertMeta := fmt.Sprintf(certMetaTemplate, serverCertID, serverCertID, "true")

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/tyk/certs/1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: serverCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `\[` + serverCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertMeta},
		}...)
	})

	t.Run("Certificate removal", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
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
		ts.Run(t, test.TestCase{Client: client, Path: "/"})
	})

	t.Run("Cipher non-match", func(t *testing.T) {

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			CipherSuites:       getCipherAliases([]string{"TLS_RSA_WITH_AES_256_CBC_SHA"}), // not matching ciphers
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}}}

		ts.Run(t, test.TestCase{Client: client, Path: "/", ErrorMatch: "tls: handshake failure"})
	})
}
