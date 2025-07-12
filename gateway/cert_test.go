package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/certs/mock"

	"github.com/TykTechnologies/tyk/internal/crypto"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

const (
	internalTLSErr          = "tls: unrecognized name"
	badcertErr              = "tls: bad certificate"
	certNotMatchErr         = "Client TLS certificate is required"
	unknownCertAuthorityErr = "unknown certificate authority"
)

func TestGatewayTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem, combinedPEM, _ := crypto.GenServerCertificate()

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
	serverCertPem, _, combinedPEM, _ := crypto.GenServerCertificate()
	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		tlsConfigCache.Flush()
	}()

	clientWithoutCert := GetTLSClient(nil, nil)
	clientCertPem, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
			// Should raise error for unknown certificate
			{ControlRequest: true, ErrorMatch: unknownCertAuthorityErr, Client: clientWithCert},
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

	t.Run("Separate domain/ control api with invalid certs", func(t *testing.T) {
		clientCertID, _, _ := certs.GetCertIDAndChainPEM(clientCertPem, "")
		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.Security.ControlAPIUseMutualTLS = true
			globalConf.ControlAPIHostname = "localhost"
			globalConf.HttpServerOptions.SSLCertificates = []string{certID}
			globalConf.Security.Certificates.ControlAPI = []string{"invalid", "invalid-" + clientCertID}
		}

		ts := StartTest(conf)
		defer ts.Close()

		certID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
		defer ts.Gw.CertificateManager.Delete(certID, "")

		clientCertID, _ = ts.Gw.CertificateManager.Add(clientCertPem, "")
		defer ts.Gw.CertificateManager.Delete(clientCertID, "")
		ts.ReloadGatewayProxy()

		// Should fail as no valid cert IDs exist in Certificates.ControlAPI
		_, _ = ts.Run(t, test.TestCase{
			Path: "/tyk/certs", Code: http.StatusForbidden, ErrorMatch: unknownCertAuthorityErr, ControlRequest: true, AdminAuth: true, Client: clientWithCert,
		})
	})

	t.Run("Separate domain/ control api with invalid + valid cert", func(t *testing.T) {
		clientCertID, _, _ := certs.GetCertIDAndChainPEM(clientCertPem, "")
		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.Security.ControlAPIUseMutualTLS = true
			globalConf.ControlAPIHostname = "localhost"
			globalConf.HttpServerOptions.SSLCertificates = []string{certID}
			globalConf.Security.Certificates.ControlAPI = []string{"invalid", clientCertID}
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

	t.Run("validate client cert against certificate authority", func(t *testing.T) {
		rootCertPEM, rootKeyPEM, err := crypto.GenerateRootCertAndKey(t)
		assert.NoError(t, err)

		serverCertPEM, serverKeyPEM, err := crypto.GenerateServerCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)
		combinedPEM := bytes.Join([][]byte{serverCertPEM.Bytes(), serverKeyPEM.Bytes()}, []byte("\n"))

		certID, _, err := certs.GetCertIDAndChainPEM(combinedPEM, "")
		assert.NoError(t, err)

		rootCertID, _, err := certs.GetCertIDAndChainPEM(rootCertPEM, "")
		assert.NoError(t, err)

		conf := func(globalConf *config.Config) {
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.HttpServerOptions.SSLInsecureSkipVerify = false
			globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
			globalConf.SuppressRedisSignalReload = true
			globalConf.Security.ControlAPIUseMutualTLS = true
			controlAPICerts := []string{"default" + rootCertID}
			globalConf.Security.Certificates = config.CertificatesConfig{
				ControlAPI: controlAPICerts,
			}
		}
		ts := StartTest(conf)
		defer ts.Close()

		certID, err = ts.Gw.CertificateManager.Add(combinedPEM, "default")
		assert.NoError(t, err)

		_, err = ts.Gw.CertificateManager.Add(rootCertPEM, "default")
		assert.NoError(t, err)
		defer ts.Gw.CertificateManager.Delete(rootCertID, "default")

		ts.ReloadGatewayProxy()

		clientCertPEM, clientKeyPEM, err := crypto.GenerateClientCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)

		clientCert, _ := tls.X509KeyPair(clientCertPEM.Bytes(), clientKeyPEM.Bytes())

		t.Run("valid client", func(t *testing.T) {
			validCertClient := GetTLSClient(&clientCert, rootCertPEM)
			_, _ = ts.Run(t, test.TestCase{
				ControlRequest: true,
				AdminAuth:      true,
				Domain:         "localhost",
				Client:         validCertClient,
				Path:           "/tyk/certs",
				Code:           http.StatusOK,
			})
		})

		t.Run("invalid client with different cert authority", func(t *testing.T) {
			_, _, _, invalidClientCert := crypto.GenCertificate(&x509.Certificate{}, false)
			tlsConfig := GetTLSConfig(&invalidClientCert, nil)
			tlsConfig.InsecureSkipVerify = false
			transport := &http.Transport{TLSClientConfig: tlsConfig}

			invalidClient := &http.Client{Transport: transport}
			u, err := url.Parse(ts.URL)

			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%s/static-mtls", u.Port()), nil)
			assert.NoError(t, err)
			_, err = invalidClient.Do(req)
			assert.ErrorContains(t, err, "tls: failed to verify certificate: x509: certificate signed by unknown authority")
		})

	})
}

// Run 2 times to ensure that both methods backward compatible
func TestAPIMutualTLS(t *testing.T) {
	t.Run("Skip ClientCA announce", func(t *testing.T) {
		testAPIMutualTLSHelper(t, true)
	})

	t.Run("Announce ClientCA", func(t *testing.T) {
		testAPIMutualTLSHelper(t, false)
	})
}

func testAPIMutualTLSHelper(t *testing.T, skipCAAnnounce bool) {
	t.Helper()

	serverCertPem, _, combinedPEM, _ := crypto.GenServerCertificate()
	certID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	expectedCertErr := unknownCertAuthorityErr
	if skipCAAnnounce {
		expectedCertErr = badcertErr
	}

	conf := func(globalConf *config.Config) {
		globalConf.EnableCustomDomains = true
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}
		globalConf.HttpServerOptions.SkipClientCAAnnouncement = skipCAAnnounce
		globalConf.ControlAPIPort = 1212
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
	clientCertPem, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
	clientCertPem2, _, _, clientCert2 := crypto.GenCertificate(&x509.Certificate{}, false)
	t.Run("acceptable CAs from server", func(t *testing.T) {
		tlsConfig := GetTLSConfig(&clientCert, serverCertPem)
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if skipCAAnnounce {
				assert.Equal(t, 0, len(info.AcceptableCAs))
			} else {
				// Even if we are loading 2 mTLS APIs where one with empty domain, because we have direct domain match it should show only cert of matching API
				assert.Equal(t, 1, len(info.AcceptableCAs))
			}
			return &clientCert, nil
		}

		transport := &http.Transport{TLSClientConfig: tlsConfig}
		httpClient := &http.Client{Transport: transport}
		clientCertID, err := ts.Gw.CertificateManager.Add(clientCertPem, "")
		clientCertID2, err := ts.Gw.CertificateManager.Add(clientCertPem2, "")
		assert.NoError(t, err)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Domain = "localhost"
			spec.Proxy.ListenPath = "/"
			spec.UseMutualTLSAuth = true
			spec.ClientCertificates = []string{clientCertID}
		},
			func(spec *APISpec) {
				spec.Domain = ""
				spec.Proxy.ListenPath = "/test"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

		_, _ = ts.Run(t, test.TestCase{
			Code: 200, Client: httpClient, Domain: "localhost",
		})

		ts.Gw.CertificateManager.Delete(clientCertID, "")
		ts.Gw.CertificateManager.Delete(clientCertID2, "")
		ts.Gw.CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})

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
				Client: client, Domain: "localhost", ErrorMatch: expectedCertErr,
			})
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _, _, _ := crypto.GenCertificate(&x509.Certificate{}, false)
			clientCertID2, _ := ts.Gw.CertificateManager.Add(clientCertPem2, "")
			defer ts.Gw.CertificateManager.Delete(clientCertID2, "")

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

			_, _ = ts.Run(t, test.TestCase{
				Client: client, ErrorMatch: expectedCertErr, Domain: "localhost",
			})
		})
	})

	t.Run("Multiple APIs on same domain", func(t *testing.T) {
		testSameDomain := func(t *testing.T, domain string) {
			t.Helper()
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

				certNotAllowedErr := `Certificate with SHA256 ` + crypto.HexSHA256(clientCert.Certificate[0]) + ` not allowed`

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
			t.Helper()
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
					ErrorMatch: expectedCertErr,
				})

				_, _ = ts.Run(t, test.TestCase{
					Path:       "/with_mutual_2",
					Client:     client,
					Domain:     domain,
					ErrorMatch: expectedCertErr,
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
							BodyMatch: `"error": "` + `Certificate with SHA256 ` + crypto.HexSHA256(clientCert.Certificate[0]) + ` not allowed`,
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
							BodyMatch: `"error": "` + `Certificate with SHA256 ` + crypto.HexSHA256(clientCert2.Certificate[0]) + ` not allowed`,
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
			t.Helper()
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
					certNotAllowedErr := `Certificate with SHA256 ` + crypto.HexSHA256(clientCert.Certificate[0]) + ` not allowed`
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
						ErrorMatch: expectedCertErr,
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
			t.Helper()
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
					certNotAllowedErr := `Certificate with SHA256 ` + crypto.HexSHA256(clientCert.Certificate[0]) + ` not allowed`
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
						ErrorMatch: expectedCertErr,
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

	_, _, combinedClientPEM, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf("request host is %s", r.Host)))
		w.WriteHeader(200)
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
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost,
				BodyMatchFunc: func(bytes []byte) bool {
					return strings.Contains(string(bytes), targetHost)
				},
				Code: http.StatusOK, Client: test.NewClientLocal()})
		})

		t.Run("PreserveHostHeader=true", func(t *testing.T) {
			api.Proxy.PreserveHostHeader = true
			ts.Gw.LoadAPI(api)

			// Giving a different value to proxy host, it should not interfere upstream certificate matching
			_, _ = ts.Run(t, test.TestCase{Domain: proxyHost,
				BodyMatchFunc: func(bytes []byte) bool {
					return strings.Contains(string(bytes), proxyHost)
				},
				Code: http.StatusOK, Client: test.NewClientLocal()})
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
	_, _, _, cert := crypto.GenCertificate(&x509.Certificate{
		EmailAddresses: []string{"test@test.com"},
		Subject:        pkix.Name{CommonName: "localhost"},
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
		globalConf.ProxySSLInsecureSkipVerify = true
		ts.Gw.SetConfig(globalConf)

		targetURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
		
		api := BuildAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = targetURL
		})[0]
		ts.Gw.LoadAPI(api)

		_, _ = ts.Run(t, test.TestCase{Code: 200, Client: test.NewClientLocal()})
	})
}

func TestKeyWithCertificateTLS(t *testing.T) {
	test.Flaky(t) // TODO TT-5112

	_, _, combinedPEM, _ := crypto.GenServerCertificate()
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
		clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
		clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
				header.Authorization: key,
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
		clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
		// Preserve the original TLS configuration when creating new transport with local dialer
		originalTransport := client.Transport.(*http.Transport)
		transport := test.NewTransport(test.WithLocalDialer())
		transport.TLSClientConfig = originalTransport.TLSClientConfig
		client.Transport = transport

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
		clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
		clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
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
			header.Authorization: key,
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

	_, _, combinedPEM, _ := crypto.GenServerCertificate()
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

	t.Run("custom domain disabled", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Certificates = []string{serverCertID}
			spec.UseKeylessAccess = true
			spec.DomainDisabled = true
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr})
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
	_, _, combinedServerPEM, serverCert := crypto.GenCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost", "tyk-gateway"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
		Subject:     pkix.Name{CommonName: "localhost"},
		Issuer:      pkix.Name{CommonName: "localhost"},
	}, true)
	serverCertID := crypto.HexSHA256(serverCert.Certificate[0])
	clientPEM, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{
		DNSNames: []string{"localhost"},
		Subject:  pkix.Name{CommonName: "localhost"},
		Issuer:   pkix.Name{CommonName: "localhost"},
	}, true)
	clientCertID := crypto.HexSHA256(clientCert.Certificate[0])
	ts := StartTest(nil)
	defer ts.Close()

	// flaky test workaround
	certIDs := ts.Gw.CertificateManager.ListAllIds("1")
	for _, certID := range certIDs {
		ts.Gw.CertificateManager.Delete(certID, "1")
	}

	t.Run("List certificates, empty", func(t *testing.T) {
		_, _ = ts.Run(t, test.TestCase{
			Path: "/tyk/certs?org_id=1", Code: 200, AdminAuth: true, BodyMatch: `{"certs":null}`,
		})
	})

	rootCertPEM, _, err := crypto.GenerateRootCertAndKey(t)
	assert.NoError(t, err)
	rootCertID, _, err := certs.GetCertIDAndChainPEM(rootCertPEM, ts.Gw.GetConfig().Secret)
	assert.NoError(t, err)

	rootCertBlock, _ := pem.Decode(rootCertPEM)
	if rootCertBlock == nil || rootCertBlock.Type != "CERTIFICATE" {
		t.Fatal("error decoding root cert")
	}
	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	assert.NoError(t, err)

	// add root cert
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost, Path: "/tyk/certs", QueryParams: map[string]string{"org_id": "1"},
		Data: string(rootCertPEM), AdminAuth: true, Code: 200, BodyMatch: `"id":"1` + rootCertID,
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
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: rootCertID},
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
						{
							ID:            "1" + rootCertID,
							IssuerCN:      rootCert.Issuer.CommonName,
							SubjectCN:     rootCert.Subject.CommonName,
							DNSNames:      rootCert.DNSNames,
							HasPrivateKey: false,
							NotAfter:      rootCert.NotAfter.UTC().Truncate(time.Second),
							NotBefore:     rootCert.NotBefore.UTC().Truncate(time.Second),
							IsCA:          true,
						},
					},
				}
				apiAllCertificateBasics := APIAllCertificateBasics{}
				_ = json.Unmarshal(data, &apiAllCertificateBasics)
				assert.ElementsMatch(t, expectedAPICertBasics.Certs, apiAllCertificateBasics.Certs)
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
			{Method: "GET", Path: "/tyk/certs/1" + rootCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `"is_ca":true`},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `\[` + serverCertMeta},
			{Method: "GET", Path: "/tyk/certs/1" + serverCertID + ",1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200, BodyMatch: clientCertMeta},
		}...)
	})

	t.Run("Certificate removal", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Method: "DELETE", Path: "/tyk/certs/1" + serverCertID + "?org_id=1", AdminAuth: true, Code: 200},
			{Method: "DELETE", Path: "/tyk/certs/1" + clientCertID + "?org_id=1", AdminAuth: true, Code: 200},
			{Method: "DELETE", Path: "/tyk/certs/1" + rootCertID + "?org_id=1", AdminAuth: true, Code: 200},
			{Method: "GET", Path: "/tyk/certs?org_id=1", AdminAuth: true, Code: 200, BodyMatch: `{"certs":null}`},
		}...)
	})
}

func TestCipherSuites(t *testing.T) {

	//configure server so we can useSSL and utilize the logic, but skip verification in the clients
	_, _, combinedPEM, _ := crypto.GenServerCertificate()
	serverCertID, _, _ := certs.GetCertIDAndChainPEM(combinedPEM, "")

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.Ciphers = []string{
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		}
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
			CipherSuites:       getCipherAliases([]string{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"}),
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}}}

		// If there is an internal TLS error it will fail test
		_, _ = ts.Run(t, test.TestCase{Client: client, Path: "/"})
	})

	t.Run("Cipher non-match", func(t *testing.T) {

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			CipherSuites:       getCipherAliases([]string{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}), // not matching ciphers
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}}}

		_, _ = ts.Run(t, test.TestCase{Client: client, Path: "/", ErrorMatch: "tls: handshake failure"})
	})
}

func TestUpstreamCertificates_WithProtocolTCP(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	cert, key, _, _ := crypto.GenCertificate(&x509.Certificate{}, false)
	certificate, _ := tls.X509KeyPair(cert, key)

	upstreamCert, _, combinedUpstreamCertPEM, _ := crypto.GenServerCertificate()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(upstreamCert)

	serverTLSConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientCAs: certPool, ClientAuth: tls.RequireAndVerifyClientCert}
	ls, err := tls.Listen("tcp", "127.0.0.1:8003", serverTLSConfig)
	assert.NoError(t, err)
	defer ls.Close()

	go listenProxyProto(ls)

	certID, err := ts.Gw.CertificateManager.Add(combinedUpstreamCertPEM, "")
	defer ts.Gw.CertificateManager.Delete(certID, "")

	ts.EnablePort(6001, "tcp")
	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "tcp"
		spec.ListenPort = 6001
		spec.Proxy.TargetURL = "tls://127.0.0.1:8003"
		spec.Proxy.Transport.SSLInsecureSkipVerify = true
		spec.UpstreamCertificates = map[string]string{
			"*": certID,
		}
	})[0]

	t.Run("enabled", func(t *testing.T) {
		client, err := net.Dial("tcp", "127.0.0.1:6001")
		assert.NoError(t, err)
		defer client.Close()

		_, _ = client.Write([]byte("ping"))
		received := make([]byte, 4)
		_, err = client.Read(received)
		assert.NoError(t, err)
		assert.Equal(t, []byte("pong"), received)
	})

	t.Run("disabled", func(t *testing.T) {
		api.UpstreamCertificates = nil
		ts.Gw.LoadAPI(api)

		client, err := net.Dial("tcp", "127.0.0.1:6001")
		assert.NoError(t, err)
		defer client.Close()

		_, _ = client.Write([]byte("ping"))
		received := make([]byte, 4)
		n, err := client.Read(received)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestClientCertificates_WithProtocolTLS(t *testing.T) {
	const (
		upstreamAddr    = "127.0.0.1:8005"
		proxyListenPort = 6005
	)

	// upstream
	upstream, err := net.Listen("tcp", upstreamAddr)
	assert.NoError(t, err)
	defer upstream.Close()

	go listenProxyProto(upstream)

	// tyk
	_, _, tykServerCombinedPEM, _ := crypto.GenServerCertificate()
	serverCertID, _, _ := certs.GetCertIDAndChainPEM(tykServerCombinedPEM, "")

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = false
		globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
	})
	defer ts.Close()

	_, _ = ts.Gw.CertificateManager.Add(tykServerCombinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(serverCertID, "")

	cert, key, combinedClientCertPEM, _ := crypto.GenServerCertificate()
	clientCertificate, err := tls.X509KeyPair(cert, key)
	assert.NoError(t, err)

	clientCertificateID, err := ts.Gw.CertificateManager.Add(combinedClientCertPEM, "")
	defer ts.Gw.CertificateManager.Delete(clientCertificateID, "")

	ts.EnablePort(proxyListenPort, "tls")
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "tls"
		spec.ListenPort = proxyListenPort
		spec.Proxy.TargetURL = "tcp://" + upstreamAddr
		spec.UseMutualTLSAuth = true
		spec.UseMutualTLSAuth = true
		spec.ClientCertificates = []string{clientCertificateID}
	}, func(spec *APISpec) {
		spec.Name = "another-api-on-control-port" // required to cover the case where there is another API in a different port.
	})

	apiAddr := fmt.Sprintf(":%d", proxyListenPort)
	mTLSConfig := &tls.Config{InsecureSkipVerify: true}

	// client
	t.Run("bad certificate", func(t *testing.T) {
		_, err := tls.Dial("tcp", apiAddr, mTLSConfig)
		assert.ErrorContains(t, err, badcertErr)
	})

	t.Run("correct certificate", func(t *testing.T) {
		mTLSConfig.Certificates = append(mTLSConfig.Certificates, clientCertificate)

		client, err := tls.Dial("tcp", apiAddr, mTLSConfig)
		assert.NoError(t, err)
		defer client.Close()

		_, _ = client.Write([]byte("ping"))
		received := make([]byte, 4)
		_, err = client.Read(received)
		assert.NoError(t, err)
		assert.Equal(t, []byte("pong"), received)
	})
}

func TestStaticMTLSAPI(t *testing.T) {
	setup := func() (*Test, string, tls.Certificate) {
		// generate certificate for gw.
		_, _, combinedPEM, _ := crypto.GenServerCertificate()
		certID, _, err := certs.GetCertIDAndChainPEM(combinedPEM, "")
		assert.NoError(t, err)

		conf := func(globalConf *config.Config) {
			globalConf.Security.ControlAPIUseMutualTLS = false
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.HttpServerOptions.SSLInsecureSkipVerify = true
			globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
			globalConf.SuppressRedisSignalReload = true
		}
		ts := StartTest(conf)

		certID, err = ts.Gw.CertificateManager.Add(combinedPEM, "default")
		assert.NoError(t, err)
		defer ts.Gw.CertificateManager.Delete(certID, "default")
		ts.ReloadGatewayProxy()

		// Initialize client certificates
		clientCertPem, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)

		clientCertID, err := ts.Gw.CertificateManager.Add(clientCertPem, "default")
		assert.NoError(t, err)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "apiID-1"
			spec.UseMutualTLSAuth = true
			spec.Proxy.ListenPath = "/static-mtls"
			spec.ClientCertificates = []string{clientCertID}
		})
		return ts, clientCertID, clientCert
	}

	t.Run("control API is not affected", func(t *testing.T) {
		ts, _, _ := setup()
		defer ts.Close()

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		_, _ = ts.Run(t, test.TestCase{
			AdminAuth: true, Path: "/tyk/apis/oas", Code: http.StatusOK, Client: &http.Client{Transport: transport},
		})
	})

	t.Run("valid client cert", func(t *testing.T) {
		ts, _, clientCert := setup()
		defer ts.Close()
		validCertClient := GetTLSClient(&clientCert, nil)
		_, _ = ts.Run(t, test.TestCase{
			Domain: "localhost",
			Client: validCertClient,
			Path:   "/static-mtls",
			Code:   http.StatusOK,
		})
	})

	t.Run("expired certificate provided by client", func(t *testing.T) {
		ts, clientCertID, _ := setup()
		defer ts.Close()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// generate a certificate which got expired 5 days ago.
		_, _, _, expiredClientCert := crypto.GenCertificate(&x509.Certificate{
			NotBefore: time.Now().AddDate(-1, 0, 0),
			NotAfter:  time.Now().AddDate(0, 0, -5),
		}, false)

		// generate expected certID from the returned certificate.
		expectedCertID := crypto.HexSHA256(expiredClientCert.Certificate[0])
		leaf := &x509.Certificate{
			Raw: expiredClientCert.Certificate[0],
			Extensions: []pkix.Extension{
				{Value: []byte(expectedCertID)},
			},
		}

		expiredClientCert.Leaf = leaf

		mockCertManager := mock.NewMockCertificateManager(ctrl)

		// CertManager.List is being called twice during the flow
		// 1 during gw.getTLSConfigForClient
		// 2 inside crypto.ValidateRequestCerts
		mockCertManager.EXPECT().List([]string{clientCertID}, certs.CertificatePublic).
			Return([]*tls.Certificate{&expiredClientCert}).Times(2)

		// replace the certificateManager with mockCertManager
		ts.Gw.CertificateManager = mockCertManager
		// generate HTTPS client with expired certificate.
		expiredClient := GetTLSClient(&expiredClientCert, nil)
		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Code:      http.StatusForbidden,
			Client:    expiredClient,
			Path:      "/static-mtls",
			BodyMatch: crypto.ErrCertExpired.Error(),
		})
	})

	t.Run("only public key in client certificate", func(t *testing.T) {
		ts, _, clientCert := setup()
		defer ts.Close()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// generate a public key
		publicKeyPEM := crypto.GenerateRSAPublicKey(t)

		certID, err := ts.Gw.CertificateManager.Add(publicKeyPEM, "")
		assert.NoError(t, err)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "apiID-2"
			spec.BaseIdentityProvidedBy = "auth_token"
			spec.UseKeylessAccess = true
			spec.UseMutualTLSAuth = true
			spec.Proxy.ListenPath = "/public-key-mtls"
			spec.ClientCertificates = []string{certID}
		})

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				assert.Zero(t, info.AcceptableCAs)
				return &clientCert, nil
			},
		}

		transport := &http.Transport{TLSClientConfig: tlsConfig}

		httpClient := &http.Client{Transport: transport}

		_, _ = ts.Run(t, test.TestCase{
			Domain:    "localhost",
			Client:    httpClient,
			AdminAuth: true,
			Path:      "/tyk/apis",
			Code:      http.StatusOK,
		})
	})

	t.Run("validate client cert against certificate authority", func(t *testing.T) {
		rootCertPEM, rootKeyPEM, err := crypto.GenerateRootCertAndKey(t)
		assert.NoError(t, err)

		serverCertPEM, serverKeyPEM, err := crypto.GenerateServerCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)
		combinedPEM := bytes.Join([][]byte{serverCertPEM.Bytes(), serverKeyPEM.Bytes()}, []byte("\n"))

		certID, _, err := certs.GetCertIDAndChainPEM(combinedPEM, "")
		assert.NoError(t, err)

		conf := func(globalConf *config.Config) {
			globalConf.Security.ControlAPIUseMutualTLS = false
			globalConf.HttpServerOptions.UseSSL = true
			globalConf.HttpServerOptions.SSLInsecureSkipVerify = false
			globalConf.HttpServerOptions.SSLCertificates = []string{"default" + certID}
			globalConf.SuppressRedisSignalReload = true
		}
		ts := StartTest(conf)
		defer ts.Close()

		certID, err = ts.Gw.CertificateManager.Add(combinedPEM, "default")
		assert.NoError(t, err)
		defer ts.Gw.CertificateManager.Delete(certID, "default")
		ts.ReloadGatewayProxy()

		clientCertPEM, clientKeyPEM, err := crypto.GenerateClientCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)

		rootCertID, err := ts.Gw.CertificateManager.Add(rootCertPEM, "default")
		assert.NoError(t, err)

		clientCert, _ := tls.X509KeyPair(clientCertPEM.Bytes(), clientKeyPEM.Bytes())

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "apiID-1"
			spec.UseMutualTLSAuth = true
			spec.Proxy.ListenPath = "/static-mtls"
			spec.ClientCertificates = []string{rootCertID}
		})

		t.Run("valid client", func(t *testing.T) {
			validCertClient := GetTLSClient(&clientCert, rootCertPEM)
			_, _ = ts.Run(t, test.TestCase{
				Domain: "localhost",
				Client: validCertClient,
				Path:   "/static-mtls",
				Code:   http.StatusOK,
			})
		})

		t.Run("invalid client with self signed certificate", func(t *testing.T) {
			_, _, _, invalidClientCert := crypto.GenCertificate(&x509.Certificate{}, false)
			tlsConfig := GetTLSConfig(&invalidClientCert, nil)
			tlsConfig.InsecureSkipVerify = false
			transport := &http.Transport{TLSClientConfig: tlsConfig}

			invalidClient := &http.Client{Transport: transport}
			u, err := url.Parse(ts.URL)

			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%s/static-mtls", u.Port()), nil)
			assert.NoError(t, err)
			_, err = invalidClient.Do(req)
			assert.ErrorContains(t, err, "tls: failed to verify certificate: x509: certificate signed by unknown authority")
		})

	})
}
