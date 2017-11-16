package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	_ "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
)

func getTLSClient(cert *tls.Certificate, caCert []byte) *http.Client {
	// Setup HTTPS client
	tlsConfig := &tls.Config{}

	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &http.Client{Transport: transport}
}

func genCertificate(template *x509.Certificate) ([]byte, []byte, []byte, tls.Certificate) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

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

func TestGatewayTLS(t *testing.T) {
	// Configure server
	serverCertPem, serverPrivPem, combinedPEM, _ := genServerCertificate()

	config.Global.HttpServerOptions.UseSSL = true
	config.Global.ListenPort = 0

	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		config.Global.HttpServerOptions.UseSSL = false
		config.Global.ListenPort = defaultListenPort
	}()

	t.Run("Without certificates", func(t *testing.T) {
		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)
		defer ln.Close()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err == nil {
			t.Error("Should raise error without certificate")
		}
	})

	t.Run("Legacy TLS certificate path", func(t *testing.T) {
		certFilePath := filepath.Join(dir, "server.crt")
		ioutil.WriteFile(certFilePath, serverCertPem, 0666)

		certKeyPath := filepath.Join(dir, "server.key")
		ioutil.WriteFile(certKeyPath, serverPrivPem, 0666)

		config.Global.HttpServerOptions.Certificates = []config.CertData{{
			Name:     "localhost",
			CertFile: certFilePath,
			KeyFile:  certKeyPath,
		}}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			ln.Close()
			os.Remove(certFilePath)
			os.Remove(certKeyPath)
			config.Global.HttpServerOptions.Certificates = []config.CertData{}
			CertificateManager.FlushCache()
		}()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("File certificate path", func(t *testing.T) {
		certPath := filepath.Join(dir, "server.pem")
		ioutil.WriteFile(certPath, combinedPEM, 0666)
		config.Global.HttpServerOptions.SSLCertificates = []string{certPath}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			config.Global.HttpServerOptions.SSLCertificates = nil
			ln.Close()
			os.Remove(certPath)
			CertificateManager.FlushCache()
		}()

		client := getTLSClient(nil, nil)
		_, err := client.Get(baseURL)

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("Redis certificate", func(t *testing.T) {
		certID, err := CertificateManager.Add(combinedPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		defer CertificateManager.Delete(certID)

		config.Global.HttpServerOptions.SSLCertificates = []string{certID}

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)

		defer func() {
			config.Global.HttpServerOptions.SSLCertificates = nil
			ln.Close()
			CertificateManager.FlushCache()
		}()

		client := getTLSClient(nil, nil)

		if _, err := client.Get(baseURL); err != nil {
			t.Error(err)
		}
	})
}

func TestGatewayControlAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, _, combinedPEM, _ := genServerCertificate()

	config.Global.HttpServerOptions.UseSSL = true
	config.Global.Security.ControlAPIUseMutualTLS = true
	config.Global.ListenPort = 0

	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
		CertificateManager.FlushCache()

		config.Global.ControlAPIHostname = ""
		config.Global.Security.ControlAPIUseMutualTLS = false
		config.Global.HttpServerOptions.UseSSL = false
		config.Global.ListenPort = defaultListenPort
	}()

	clientCertPem, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientWithCert := getTLSClient(&clientCert, serverCertPem)

	clientWithoutCert := getTLSClient(nil, nil)

	t.Run("Separate domain", func(t *testing.T) {
		certID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(certID)

		config.Global.ControlAPIHostname = "localhost"
		config.Global.HttpServerOptions.SSLCertificates = []string{certID}

		ln, _ := generateListener(0)
		baseControlAPIURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "127.0.0.1", -1)
		listen(ln, nil, nil)

		defer func() {
			ln.Close()
			CertificateManager.FlushCache()
			config.Global.HttpServerOptions.SSLCertificates = nil
			config.Global.Security.Certificates.ControlAPI = nil
		}()

		if _, err := clientWithoutCert.Get(baseURL); err != nil {
			t.Error("Should acess tyk without client certificates", err)
		}

		if _, err := clientWithoutCert.Get(baseControlAPIURL); err == nil {
			t.Error("Should raise error for ControlAPI without certificate")
		}

		if _, err := clientWithCert.Get(baseControlAPIURL); err == nil {
			t.Error("Should raise error for for unknown certificate")
		}

		clientCertID, _ := CertificateManager.Add(clientCertPem, "")
		defer CertificateManager.Delete(clientCertID)

		config.Global.Security.Certificates.ControlAPI = []string{clientCertID}

		if _, err := clientWithCert.Get(baseControlAPIURL); err != nil {
			t.Error("Should pass request with valid client cert", err)
		}
	})

	t.Run("Same domain", func(t *testing.T) {
		certID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(certID)

		config.Global.ControlAPIHostname = "localhost"
		config.Global.HttpServerOptions.SSLCertificates = []string{certID}

		certPath := filepath.Join(dir, "client.pem")
		ioutil.WriteFile(certPath, clientCertPem, 0666)

		ln, _ := generateListener(0)
		baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "127.0.0.1", -1)
		listen(ln, nil, nil)
		loadAPIEndpoints(mainRouter)
		defer func() {
			ln.Close()
			config.Global.HttpServerOptions.SSLCertificates = nil
			config.Global.Security.Certificates.ControlAPI = nil
			CertificateManager.FlushCache()
		}()

		if _, err := clientWithoutCert.Get(baseURL); err != nil {
			t.Error("Should acess tyk without client certificates", err)
		}

		req, _ := http.NewRequest("GET", baseURL+"/tyk/reload", nil)
		respJSON := struct {
			Message string `json:"message"`
		}{}

		if resp, err := clientWithoutCert.Do(withAuth(req)); err != nil {
			t.Error("Should not raise TLS without certificate", err)
		} else {
			json.NewDecoder(resp.Body).Decode(&respJSON)
			if respJSON.Message != `Client TLS certificate is required` {
				t.Error("Error not match:", respJSON.Message)
			}
		}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should not raise TLS for for unknown certificate", err)
		} else {
			json.NewDecoder(resp.Body).Decode(&respJSON)
			expectedErr := `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`

			if respJSON.Message != expectedErr {
				t.Error("Error not match:", respJSON.Message, expectedErr)
			}
		}

		clientCertID, _ := CertificateManager.Add(clientCertPem, "")

		config.Global.Security.Certificates.ControlAPI = []string{clientCertID}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should pass request with valid client cert", err)
		} else {
			if resp.StatusCode != 200 {
				body, _ := ioutil.ReadAll(resp.Body)
				t.Error("Should be valid requests:", string(body))
			}
		}

		CertificateManager.Delete(clientCertID)

		config.Global.Security.Certificates.ControlAPI = []string{certPath}

		if resp, err := clientWithCert.Do(withAuth(req)); err != nil {
			t.Error("Should pass request with valid client cert", err)
		} else {
			if resp.StatusCode != 200 {
				body, _ := ioutil.ReadAll(resp.Body)
				t.Error("Should be valid requests:", string(body))
			}
		}
	})
}

func TestAPIMutualTLS(t *testing.T) {
	// Configure server
	serverCertPem, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID)

	config.Global.EnableCustomDomains = true
	config.Global.ListenAddress = "127.0.0.1"
	config.Global.HttpServerOptions.UseSSL = true
	config.Global.ListenPort = 0
	config.Global.HttpServerOptions.SSLCertificates = []string{certID}

	ln, _ := generateListener(0)
	listen(ln, nil, nil)

	defer func() {
		ln.Close()
		config.Global.EnableCustomDomains = false
		config.Global.ListenAddress = ""
		config.Global.HttpServerOptions.SSLCertificates = nil
		config.Global.HttpServerOptions.UseSSL = false
		config.Global.ListenPort = defaultListenPort
	}()

	// Initialize client certificates
	clientCertPem, _, _, clientCert := genCertificate(&x509.Certificate{})

	// Start of the tests
	// To make SSL SNI work we need to use domains
	baseURL := "https://" + strings.Replace(ln.Addr().String(), "127.0.0.1", "localhost", -1)

	t.Run("SNI and domain per API", func(t *testing.T) {
		t.Run("API without mutual TLS", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
			})

			if resp, err := client.Get(baseURL); err != nil {
				t.Error("Should work as ordinary api", err)
			} else if resp.StatusCode != 200 {
				t.Error("Should load API", resp)
			}
		})

		t.Run("MutualTLSCertificate not set", func(t *testing.T) {
			client := getTLSClient(nil, nil)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
			})

			if _, err := client.Get(baseURL); err == nil {
				t.Error("Should reject unknown certificate")
			}
		})

		t.Run("Client certificate match", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)
			clientCertID, _ := CertificateManager.Add(clientCertPem, "")

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID}
			})

			if resp, err := client.Get(baseURL); err != nil {
				t.Error("Mutual TLS should work", err)
			} else if resp.StatusCode != 200 {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Error("Should be valid request", resp, string(b))
			}

			CertificateManager.Delete(clientCertID)

			if _, err := client.Get(baseURL); err == nil {
				t.Error("Should error if certificate revoked")
			}
		})

		t.Run("Client certificate differ", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			clientCertPem2, _, _, _ := genCertificate(&x509.Certificate{})
			clientCertID2, _ := CertificateManager.Add(clientCertPem2, "")
			defer CertificateManager.Delete(clientCertID2)

			buildAndLoadAPI(func(spec *APISpec) {
				spec.Domain = "localhost"
				spec.Proxy.ListenPath = "/"
				spec.UseMutualTLSAuth = true
				spec.ClientCertificates = []string{clientCertID2}
			})

			if _, err := client.Get(baseURL); err == nil {
				t.Error("Should reject wrong certificate")
			}
		})
	})

	t.Run("Multiple APIs on same domain", func(t *testing.T) {
		clientCertID, _ := CertificateManager.Add(clientCertPem, "")
		defer CertificateManager.Delete(clientCertID)

		loadAPIS := func(certs ...string) {
			buildAndLoadAPI(
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/with_mutual"
					spec.UseMutualTLSAuth = true
					spec.ClientCertificates = certs
				},
				func(spec *APISpec) {
					spec.Proxy.ListenPath = "/without_mutual"
				},
			)
		}

		respJSON := struct {
			Error string `json:"error"`
		}{}

		t.Run("Without certificate", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)
			clientWithoutCert := getTLSClient(nil, nil)

			loadAPIS()

			if resp, err := clientWithoutCert.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				json.NewDecoder(resp.Body).Decode(&respJSON)

				if resp.StatusCode != 403 || respJSON.Error != `Client TLS certificate is required` {
					t.Error("Error not match:", respJSON.Error, resp.StatusCode)
				}
			}

			if resp, err := client.Get(baseURL + "/without_mutual"); err != nil {
				t.Error("Should not error", err)
			} else if resp.StatusCode != 200 {
				t.Error("Should process request", resp.StatusCode)
			}
		})

		t.Run("Client certificate not match", func(t *testing.T) {
			client := getTLSClient(&clientCert, serverCertPem)

			loadAPIS()

			if resp, err := client.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				expectedErr := `Certificate with SHA256 ` + certs.HexSHA256(clientCert.Certificate[0]) + ` not allowed`
				json.NewDecoder(resp.Body).Decode(&respJSON)

				if resp.StatusCode != 403 || respJSON.Error != expectedErr {
					t.Error("Error not match:", respJSON.Error, expectedErr, resp.StatusCode)
				}
			}
		})

		t.Run("Client certificate match", func(t *testing.T) {
			loadAPIS(clientCertID)

			client := getTLSClient(&clientCert, serverCertPem)

			if resp, err := client.Get(baseURL + "/with_mutual"); err != nil {
				t.Error("Should reject on HTTP level", err)
			} else {
				if resp.StatusCode != 200 {
					t.Error("Error not match:", resp.StatusCode)
				}
			}
		})
	})
}

func TestUpstreamMutualTLS(t *testing.T) {
	_, _, combinedClientPEM, clientCert := genCertificate(&x509.Certificate{})
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	pool := x509.NewCertPool()
	ts.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
	}
	ts.StartTLS()
	defer ts.Close()

	t.Run("Without API", func(t *testing.T) {
		client := getTLSClient(&clientCert, nil)

		if _, err := client.Get(ts.URL); err == nil {
			t.Error("Should reject without certificate")
		}

		pool.AddCert(clientCert.Leaf)

		if _, err := client.Get(ts.URL); err != nil {
			t.Error("Should pass with valid certificate")
		}
	})

	t.Run("Upstream API", func(t *testing.T) {
		clientCertID, _ := CertificateManager.Add(combinedClientPEM, "")
		defer CertificateManager.Delete(clientCertID)

		pool.AddCert(clientCert.Leaf)

		ln, _ := generateListener(0)
		baseURL := "http://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)
		listen(ln, nil, nil)
		config.Global.ProxySSLInsecureSkipVerify = true
		defer func() {
			ln.Close()
			config.Global.ProxySSLInsecureSkipVerify = false
		}()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = ts.URL
			spec.UpstreamCertificates = map[string]string{
				"*": clientCertID,
			}
		})

		client := getTLSClient(nil, nil)

		if resp, err := client.Get(baseURL); err != nil {
			t.Error(err)
		} else if resp.StatusCode != 200 {
			t.Error("Should pass pass request with valid upstream certificate", resp)
		}
	})
}

func TestKeyWithCertificateTLS(t *testing.T) {
	_, _, combinedPEM, _ := genServerCertificate()
	serverCertID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(serverCertID)

	_, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])

	config.Global.HttpServerOptions.UseSSL = true
	config.Global.ListenPort = 0
	config.Global.HttpServerOptions.SSLCertificates = []string{serverCertID}

	ln, _ := generateListener(0)
	listen(ln, nil, nil)

	defer func() {
		ln.Close()
		config.Global.HttpServerOptions.SSLCertificates = nil
		config.Global.HttpServerOptions.UseSSL = false
		config.Global.ListenPort = defaultListenPort
	}()

	apis := buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.BaseIdentityProvidedBy = apidef.AuthToken
		spec.Auth.UseCertificate = true
		spec.Proxy.ListenPath = "/"
	})

	baseURL := "https://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1)

	client := getTLSClient(&clientCert, nil)

	if resp, err := client.Get(baseURL); err != nil {
		t.Fatal("Should pass without errors", err)
	} else if resp.StatusCode != 403 {
		t.Fatal("Should not pass without key", resp)
	}

	token := createParamAuthSession(apis[0].APIID)
	token.Certificate = clientCertID

	tokenJSON, _ := json.Marshal(token)
	req, _ := http.NewRequest("POST", baseURL+"/tyk/keys/create", bytes.NewReader(tokenJSON))

	if resp, _ := client.Do(withAuth(req)); resp.StatusCode != 200 {
		t.Fatal("Should create a key", resp)
	}

	if resp, _ := client.Get(baseURL); resp.StatusCode != 200 {
		t.Fatal("Should recognize key based on client certificate", resp)
	}
}

func TestCertificateHandlerTLS(t *testing.T) {
	_, _, combinedServerPEM, serverCert := genServerCertificate()
	serverCertID := certs.HexSHA256(serverCert.Certificate[0])

	clientPEM, _, _, clientCert := genCertificate(&x509.Certificate{})
	clientCertID := certs.HexSHA256(clientCert.Certificate[0])

	config.Global.ListenPort = 0

	ln, _ := generateListener(0)
	listen(ln, nil, nil)
	defer func() {
		CertificateManager.FlushCache()
		ln.Close()
		config.Global.ListenPort = defaultListenPort
	}()

	baseURL := "http://" + strings.Replace(ln.Addr().String(), "[::]", "localhost", -1) + "/tyk/certs/"

	var req *http.Request
	client := &http.Client{}

	t.Run("List certificates, empty", func(t *testing.T) {
		req, _ := http.NewRequest("GET", baseURL, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp APIAllCertificates
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if len(apiResp.CertIDs) != 0 {
				t.Error("Should return empty list:", apiResp)
			}
		}
	})

	t.Run("Should add certificates with and without private keys", func(t *testing.T) {
		// Public Certificate
		req, _ = http.NewRequest("POST", baseURL, bytes.NewReader(clientPEM))
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp APICertificateStatusMessage
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if apiResp.CertID != clientCertID {
				t.Error("Should create certificate:", apiResp)
			}
		}

		// Server certificate with private key
		req, _ = http.NewRequest("POST", baseURL, bytes.NewReader(combinedServerPEM))
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp APICertificateStatusMessage
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if apiResp.CertID != serverCertID {
				t.Error("Should create certificate:", apiResp)
			}
		}
	})

	t.Run("List certificates, non empty", func(t *testing.T) {
		// Should list 2 newly created certificates
		req, _ = http.NewRequest("GET", baseURL, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Fatal("Response:", resp, err)
		} else {
			var apiResp APIAllCertificates
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if len(apiResp.CertIDs) != 2 {
				t.Error("Should return valid meta:", apiResp)
			}
		}
	})

	t.Run("Certificate meta info", func(t *testing.T) {
		req, _ = http.NewRequest("GET", baseURL+clientCertID, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp certs.CertificateMeta
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if apiResp.ID != clientCertID {
				t.Error("Should return valid meta:", apiResp)
			}

			if apiResp.HasPrivateKey {
				t.Error("Should be marked as having public only key", apiResp)
			}
		}

		req, _ = http.NewRequest("GET", baseURL+serverCertID, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp certs.CertificateMeta
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if apiResp.ID != serverCertID {
				t.Error("Should return valid meta:", apiResp)
			}

			if !apiResp.HasPrivateKey {
				t.Error("Should be marked as having private key", apiResp)
			}

			if apiResp.DNSNames[0] != "localhost" {
				t.Error("Should fill all the fields", apiResp)
			}
		}

		req, _ = http.NewRequest("GET", baseURL+clientCertID+","+serverCertID, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp []certs.CertificateMeta
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if apiResp[0].ID != clientCertID {
				t.Error("Should return valid meta:", apiResp[0].ID, clientCertID)
			}

			if apiResp[1].ID != serverCertID {
				t.Error("Should return valid meta:", apiResp[1].ID, serverCertID)
			}
		}
	})

	t.Run("Certificate removal", func(t *testing.T) {
		req, _ = http.NewRequest("DELETE", baseURL+serverCertID, nil)
		client.Do(withAuth(req))

		req, _ = http.NewRequest("DELETE", baseURL+clientCertID, nil)
		client.Do(withAuth(req))

		// List certificates, empty
		req, _ = http.NewRequest("GET", baseURL, nil)
		if resp, err := client.Do(withAuth(req)); resp == nil || resp.StatusCode != 200 {
			t.Error("Response:", resp, err)
		} else {
			var apiResp APIAllCertificates
			json.NewDecoder(resp.Body).Decode(&apiResp)

			if len(apiResp.CertIDs) != 0 {
				t.Error("Should return empty list:", apiResp)
			}
		}
	})
}
