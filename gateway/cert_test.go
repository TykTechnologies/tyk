package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func genCertificate(template *x509.Certificate) ([]byte, []byte, []byte, tls.Certificate) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(time.Hour)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem, keyPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	clientCert, _ := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())

	combinedPEM := bytes.Join([][]byte{certPem.Bytes(), keyPem.Bytes()}, []byte("\n"))

	return certPem.Bytes(), keyPem.Bytes(), combinedPEM, clientCert
}

func genServerCertificate() ([]byte, []byte, []byte, tls.Certificate) {
	certPem, privPem, combinedPEM, cert := genCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	})

	return certPem, privPem, combinedPEM, cert
}

const (
	internalTLSErr  = "tls: unrecognized name"
	badcertErr      = "tls: bad certificate"
	certNotMatchErr = "Client TLS certificate is required"
)

func TestGatewayTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem, combinedPEM, _ := genServerCertificate()

	dir, _ := ioutil.TempDir("", "certs")
	defer os.RemoveAll(dir)

	client := GetTLSClient(nil, nil)

	t.Run("Without certificates", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.UseSSL = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr, Client: client})
	})

	t.Run("Legacy TLS certificate path", func(t *testing.T) {
		certFilePath := filepath.Join(dir, "server.crt")
		ioutil.WriteFile(certFilePath, serverCertPem, 0666)

		certKeyPath := filepath.Join(dir, "server.key")
		ioutil.WriteFile(certKeyPath, serverPrivPem, 0666)

		globalConf := config.Global()
		globalConf.HttpServerOptions.Certificates = []config.CertData{{
			Name:     "localhost",
			CertFile: certFilePath,
			KeyFile:  certKeyPath,
		}}
		globalConf.HttpServerOptions.UseSSL = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{Code: 200, Client: client})

		CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})

	t.Run("File certificate path", func(t *testing.T) {
		certPath := filepath.Join(dir, "server.pem")
		ioutil.WriteFile(certPath, combinedPEM, 0666)

		globalConf := config.Global()
		globalConf.HttpServerOptions.SSLCertificates = []string{certPath}
		globalConf.HttpServerOptions.UseSSL = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{Code: 200, Client: client})

		CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})

	t.Run("Redis certificate", func(t *testing.T) {
		certID, err := CertificateManager.Add(combinedPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		defer CertificateManager.Delete(certID, "")

		globalConf := config.Global()
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}
		globalConf.HttpServerOptions.UseSSL = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{Code: 200, Client: client})

		CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	})
}

func TestGatewayControlAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, _, combinedPEM, _ := genServerCertificate()

	globalConf := config.Global()
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.Security.ControlAPIUseMutualTLS = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		CertificateManager.FlushCache()
		tlsConfigCache.Flush()
	}()

	clientCertPem, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientWithCert := GetTLSClient(&clientCert, serverCertPem)

	clientWithoutCert := GetTLSClient(nil, nil)

	t.Run("Separate domain", func(t *testing.T) {
		certID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(certID, "")

		globalConf := config.Global()
		globalConf.ControlAPIHostname = "localhost"
		globalConf.HttpServerOptions.SSLCertificates = []string{certID}
		config.SetGlobal(globalConf)

		ts := StartTest()
		defer ts.Close()

		defer func() {
			CertificateManager.FlushCache()
			tlsConfigCache.Flush()
			globalConf := config.Global()
			globalConf.HttpServerOptions.SSLCertificates = nil
			globalConf.Security.Certificates.ControlAPI = nil
			config.SetGlobal(globalConf)
		}()

		unknownErr := "x509: certificate signed by unknown authority"

		ts.Run(t, []test.TestCase{
			// Should acess tyk without client certificates
			{Client: clientWithoutCert},
			// Should raise error for ControlAPI without certificate
			{ControlRequest: true, ErrorMatch: unknownErr},
			// Should raise error for for unknown certificate
			{ControlRequest: true, ErrorMatch: badcertErr, Client: clientWithCert},
		}...)

		clientCertID, _ := CertificateManager.Add(clientCertPem, "")
		defer CertificateManager.Delete(clientCertID, "")

		globalConf = config.Global()
		globalConf.Security.Certificates.ControlAPI = []string{clientCertID}
		config.SetGlobal(globalConf)

		// Should pass request with valid client cert
		ts.Run(t, test.TestCase{
			Path: "/tyk/certs", Code: 200, ControlRequest: true, AdminAuth: true, Client: clientWithCert,
		})
	})
}

func TestAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	globalConf := config.Global()
	globalConf.EnableCustomDomains = true
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.ListenPort = 0
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	// Initialize client certificates
	clientCertPem, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientCertPem2, _, _, clientCert2 := genCertificate(&x509.Certificate{})

	t.Run("SNI and domain per API", func(t *testing.T) {
		t.Run("API without mutual TLS", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)

			BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
			})

			ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client, Domain: "localhost"})
		})

		t.Run("MutualTLSCertificate not set", func(t *testing.T) {
			client := GetTLSClient(nil, nil)

			BuildAndLoadAPI(func(spec *APISpec) {
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
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")

			BuildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID}
			})

			ts.Run(t, test.TestCase{
				Code: 200, Client: client, Domain: "localhost",
			})

			CertificateManager.Delete(clientCertID, "")
			CertificateManager.FlushCache()
			tlsConfigCache.Flush()

			client = GetTLSClient(&clientCert, serverCertPem)
			ts.Run(t, test.TestCase{
				Client: client, Domain: "localhost", ErrorMatch: badcertErr,
			})
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := GetTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _, _, _ := genCertificate(&x509.Certificate{})
			clientCertID2, _ := CertificateManager.Add(clientCertPem2, "")
			defer CertificateManager.Delete(clientCertID2, "")

			BuildAndLoadAPI(func(spec *APISpec) {
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
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")
			defer CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				BuildAndLoadAPI(
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
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")
			defer CertificateManager.Delete(clientCertID, "")

			clientCertID2, _ := CertificateManager.Add(clientCertPem2, "")
			defer CertificateManager.Delete(clientCertID2, "")

			loadAPIS := func(certs []string, certs2 []string) {
				BuildAndLoadAPI(
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
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")
			defer CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				BuildAndLoadAPI(
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
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")
			defer CertificateManager.Delete(clientCertID, "")

			loadAPIS := func(certs ...string) {
				BuildAndLoadAPI(
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
	_, _, combinedClientPEM, clientCert := genCertificate(&x509.Certificate{})
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
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		clientCertID, _ := CertificateManager.Add(combinedClientPEM, "")
		defer CertificateManager.Delete(clientCertID, "")

		pool.AddCert(clientCert.Leaf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.UpstreamCertificates = map[string]string{
				"*": clientCertID,
			}
		})

		// Should pass with valid upstream certificate
		ts.Run(t, test.TestCase{Code: 200})
	})

}

func TestSSLForceCommonName(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	// generate certificate Common Name as valid hostname and SAN as non-empty value
	_, _, _, cert := genCertificate(&x509.Certificate{
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
		ts := StartTest()
		defer ts.Close()

		targetURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = targetURL
		})
		ts.Run(t, test.TestCase{Code: 500, BodyMatch: "There was a problem proxying the request"})
	})

	t.Run("Force Common Name Check is Enabled", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.SSLForceCommonNameCheck = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		targetURL := strings.Replace(upstream.URL, "127.0.0.1", "host1.local", 1)
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = targetURL
		})

		ts.Run(t, test.TestCase{Code: 200})
	})
}

func TestKeyWithCertificateTLS(t *testing.T) {
	_, _, combinedPEM, _ := genServerCertificate()
	serverCertID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(serverCertID, "")

	globalConf := config.Global()
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.EnableCustomDomains = true
	globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	orgId := "default"
	t.Run("Without domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
		clientCertID, err := CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		BuildAndLoadAPI(func(spec *APISpec) {
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
				s.SetAccessRights(map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}})
			})

			if key == "" {
				t.Fatal("Should create key based on certificate")
			}

			_, key = ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.SetAccessRights(map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}})
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
		clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
		clientCertID, err := CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		BuildAndLoadAPI(
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
				s.SetAccessRights(map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}})
			})

			if key == "" {
				t.Fatal("Should create key based on certificate")
			}

			_, key = ts.CreateSession(func(s *user.SessionState) {
				s.Certificate = clientCertID
				s.SetAccessRights(map[string]user.AccessDefinition{"test": {
					APIID: "test", Versions: []string{"v1"},
				}})
			})

			if key != "" {
				t.Fatal("Should not allow create key based on the same certificate")
			}

			ts.Run(t, test.TestCase{Path: "/test1", Code: 404, Client: client})

			// Domain is not set, but we still pass it, it should still work
			ts.Run(t, test.TestCase{Path: "/test1", Code: 200, Domain: "localhost", Client: client})
		})
	})

	t.Run("With regex custom domain", func(t *testing.T) {
		clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
		clientCertID, err := CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		api := BuildAndLoadAPI(
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
			s.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID, Versions: []string{"v1"},
			}})
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Path: "/test1", Domain: "host2", Client: client})
	})

	// check that a key no longer works after the cert is removed
	t.Run("Cert removed", func(t *testing.T) {
		clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
		clientCertID, err := CertificateManager.Add(clientPEM, orgId)

		if err != nil {
			t.Fatal("certificate should be added to cert manager")
		}

		BuildAndLoadAPI(func(spec *APISpec) {
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
			s.SetAccessRights(map[string]user.AccessDefinition{"test": {
				APIID: "test", Versions: []string{"v1"},
			}})
		})

		if key == "" {
			t.Fatal("Should create key based on certificate")
		}

		// check we can use the key after remove the cert
		ts.Run(t, test.TestCase{Path: "/", Code: 200, Client: client})
		CertificateManager.Delete(clientCertID, orgId)
		// now we should not be allowed to use the key
		ts.Run(t, test.TestCase{Path: "/", Code: 403, Client: client})
	})

}

func TestAPICertificate(t *testing.T) {
	_, _, combinedPEM, _ := genServerCertificate()
	serverCertID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(serverCertID, "")

	globalConf := config.Global()
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.HttpServerOptions.SSLCertificates = []string{}
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}}}

	t.Run("Cert set via API", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Certificates = []string{serverCertID}
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{Code: 200, Client: client})
	})

	t.Run("Cert unknown", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, test.TestCase{ErrorMatch: internalTLSErr})
	})
}

func TestCertificateHandlerTLS(t *testing.T) {
	_, _, combinedServerPEM, serverCert := genServerCertificate()
	serverCertID := certs.HexSHA256(serverCert.Certificate[0])

	clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])

	ts := StartTest()
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
	_, _, combinedPEM, _ := genServerCertificate()
	serverCertID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(serverCertID, "")

	globalConf := config.Global()
	globalConf.HttpServerOptions.UseSSL = true
	globalConf.HttpServerOptions.Ciphers = []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"}
	globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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
