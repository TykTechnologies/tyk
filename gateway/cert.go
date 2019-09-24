package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/gorilla/mux"
)

type APICertificateStatusMessage struct {
	CertID  string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type APIAllCertificates struct {
	CertIDs []string `json:"certs"`
}

var cipherSuites = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                0x0005,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           0x000a,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            0x002f,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            0x0035,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         0x003c,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         0x009c,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         0x009d,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        0xc007,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    0xc009,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    0xc00a,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          0xc011,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     0xc012,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      0xc013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      0xc014,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xc023,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   0xc027,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   0xc02f,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xc02b,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   0xc030,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xc02c,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    0xcca8,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  0xcca9,
}

var certLog = log.WithField("prefix", "certs")

func getUpstreamCertificate(host string, spec *APISpec) (cert *tls.Certificate) {
	var certID string

	certMaps := []map[string]string{config.Global().Security.Certificates.Upstream}

	if spec != nil && spec.UpstreamCertificates != nil {
		certMaps = append(certMaps, spec.UpstreamCertificates)
	}

	for _, m := range certMaps {
		if len(m) == 0 {
			continue
		}

		if id, ok := m["*"]; ok {
			certID = id
		}

		hostParts := strings.SplitN(host, ".", 2)
		if len(hostParts) > 1 {
			hostPattern := "*." + hostParts[1]

			if id, ok := m[hostPattern]; ok {
				certID = id
			}
		}

		if id, ok := m[host]; ok {
			certID = id
		}
	}

	if certID == "" {
		return nil
	}

	certs := CertificateManager.List([]string{certID}, certs.CertificatePrivate)

	if len(certs) == 0 {
		return nil
	}

	return certs[0]
}

func verifyPeerCertificatePinnedCheck(spec *APISpec, tlsConfig *tls.Config) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if (spec == nil || len(spec.PinnedPublicKeys) == 0) && len(config.Global().Security.PinnedPublicKeys) == 0 {
		return nil
	}

	tlsConfig.InsecureSkipVerify = true

	whitelist := getPinnedPublicKeys("*", spec)
	if len(whitelist) == 0 {
		return nil
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certLog.Debug("Checking certificate public key")

		for _, rawCert := range rawCerts {
			cert, _ := x509.ParseCertificate(rawCert)
			pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				continue
			}

			fingerprint := certs.HexSHA256(pub)

			for _, w := range whitelist {
				if w == fingerprint {
					return nil
				}
			}
		}

		return errors.New("Certificate public key pinning error. Public keys do not match.")
	}
}

func dialTLSPinnedCheck(spec *APISpec, tc *tls.Config) func(network, addr string) (net.Conn, error) {
	if (spec == nil || len(spec.PinnedPublicKeys) == 0) && len(config.Global().Security.PinnedPublicKeys) == 0 {
		return nil
	}

	return func(network, addr string) (net.Conn, error) {
		clone := tc.Clone()
		clone.InsecureSkipVerify = true

		c, err := tls.Dial(network, addr, clone)
		if err != nil {
			return c, err
		}

		host, _, _ := net.SplitHostPort(addr)
		whitelist := getPinnedPublicKeys(host, spec)
		if len(whitelist) == 0 {
			return c, nil
		}

		certLog.Debug("Checking certificate public key for host:", host)

		state := c.ConnectionState()
		for _, peercert := range state.PeerCertificates {
			der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
			if err != nil {
				continue
			}
			fingerprint := certs.HexSHA256(der)

			for _, w := range whitelist {
				if w == fingerprint {
					return c, nil
				}
			}
		}

		return nil, errors.New("https://" + host + " certificate public key pinning error. Public keys do not match.")
	}
}

func getPinnedPublicKeys(host string, spec *APISpec) (fingerprint []string) {
	var keyIDs string

	pinMaps := []map[string]string{config.Global().Security.PinnedPublicKeys}

	if spec != nil && spec.PinnedPublicKeys != nil {
		pinMaps = append(pinMaps, spec.PinnedPublicKeys)
	}

	for _, m := range pinMaps {
		if len(m) == 0 {
			continue
		}

		if id, ok := m["*"]; ok {
			keyIDs = id
		}

		hostParts := strings.SplitN(host, ".", 2)
		if len(hostParts) > 1 {
			hostPattern := "*." + hostParts[1]

			if id, ok := m[hostPattern]; ok {
				keyIDs = id
			}
		}

		if id, ok := m[host]; ok {
			keyIDs = id
		}
	}

	if keyIDs == "" {
		return nil
	}

	return CertificateManager.ListPublicKeys(strings.Split(keyIDs, ","))
}

// dummyGetCertificate needed because TLSConfig require setting Certificates array or GetCertificate function from start, even if it get overriden by `getTLSConfigForClient`
func dummyGetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func getTLSConfigForClient(baseConfig *tls.Config, listenPort int) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {

	// Supporting legacy certificate configuration
	serverCerts := []tls.Certificate{}
	certNameMap := map[string]*tls.Certificate{}

	for _, certData := range config.Global().HttpServerOptions.Certificates {
		cert, err := tls.LoadX509KeyPair(certData.CertFile, certData.KeyFile)
		if err != nil {
			log.Errorf("Server error: loadkeys: %s", err)
			continue
		}
		serverCerts = append(serverCerts, cert)
		certNameMap[certData.Name] = &cert
	}

	for _, cert := range CertificateManager.List(config.Global().HttpServerOptions.SSLCertificates, certs.CertificatePrivate) {
		if cert != nil {
			serverCerts = append(serverCerts, *cert)
		}
	}

	baseConfig.Certificates = serverCerts

	baseConfig.BuildNameToCertificate()
	for name, cert := range certNameMap {
		baseConfig.NameToCertificate[name] = cert
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		newConfig := baseConfig.Clone()

		isControlAPI := (listenPort != 0 && config.Global().ControlAPIPort == listenPort) || (config.Global().ControlAPIHostname == hello.ServerName)

		if isControlAPI && config.Global().Security.ControlAPIUseMutualTLS {
			newConfig.ClientAuth = tls.RequireAndVerifyClientCert
			newConfig.ClientCAs = CertificateManager.CertPool(config.Global().Security.Certificates.ControlAPI)

			return newConfig, nil
		}

		apisMu.RLock()
		defer apisMu.RUnlock()

		// Dynamically add API specific certificates
		for _, spec := range apiSpecs {
			if len(spec.Certificates) != 0 {
				for _, cert := range CertificateManager.List(spec.Certificates, certs.CertificatePrivate) {
					if cert == nil {
						continue
					}
					newConfig.Certificates = append(newConfig.Certificates, *cert)

					if cert != nil {
						if len(cert.Leaf.Subject.CommonName) > 0 {
							newConfig.NameToCertificate[cert.Leaf.Subject.CommonName] = cert
						}
						for _, san := range cert.Leaf.DNSNames {
							newConfig.NameToCertificate[san] = cert
						}
					}
				}
			}
		}

		for _, spec := range apiSpecs {
			if spec.UseMutualTLSAuth && spec.Domain != "" && spec.Domain == hello.ServerName {
				newConfig.ClientAuth = tls.RequireAndVerifyClientCert
				certIDs := append(spec.ClientCertificates, config.Global().Security.Certificates.API...)
				newConfig.ClientCAs = CertificateManager.CertPool(certIDs)
				break
			}
		}

		// No mutual tls APIs with matched domain found
		// Check if one of APIs without domain, require asking client cert
		if newConfig.ClientAuth == tls.NoClientCert {
			for _, spec := range apiSpecs {
				if spec.Auth.UseCertificate || (spec.Domain == "" && spec.UseMutualTLSAuth) {
					newConfig.ClientAuth = tls.RequestClientCert
					break
				}
			}
		}

		return newConfig, nil
	}
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	certID := mux.Vars(r)["certID"]

	switch r.Method {
	case "POST":
		content, err := ioutil.ReadAll(r.Body)
		if err != nil {
			doJSONWrite(w, 405, apiError("Malformed request body"))
			return
		}

		orgID := r.URL.Query().Get("org_id")
		var certID string
		if certID, err = CertificateManager.Add(content, orgID); err != nil {
			doJSONWrite(w, http.StatusForbidden, apiError(err.Error()))
			return
		}

		doJSONWrite(w, http.StatusOK, &APICertificateStatusMessage{certID, "ok", "Certificate added"})
	case "GET":
		if certID == "" {
			orgID := r.URL.Query().Get("org_id")

			certIds := CertificateManager.ListAllIds(orgID)
			doJSONWrite(w, http.StatusOK, &APIAllCertificates{certIds})
			return
		}

		certIDs := strings.Split(certID, ",")
		certificates := CertificateManager.List(certIDs, certs.CertificateAny)

		if len(certIDs) == 1 {
			if certificates[0] == nil {
				doJSONWrite(w, http.StatusNotFound, apiError("Certificate with given SHA256 fingerprint not found"))
				return
			}

			doJSONWrite(w, http.StatusOK, certs.ExtractCertificateMeta(certificates[0], certIDs[0]))
			return
		} else {
			var meta []*certs.CertificateMeta
			for ci, cert := range certificates {
				if cert != nil {
					meta = append(meta, certs.ExtractCertificateMeta(cert, certIDs[ci]))
				} else {
					meta = append(meta, nil)
				}
			}

			doJSONWrite(w, http.StatusOK, meta)
			return
		}
	case "DELETE":
		CertificateManager.Delete(certID)
		doJSONWrite(w, http.StatusOK, &apiStatusMessage{"ok", "removed"})
	}
}

func getCipherAliases(ciphers []string) (cipherCodes []uint16) {
	for k, v := range cipherSuites {
		for _, str := range ciphers {
			if str == k {
				cipherCodes = append(cipherCodes, v)
			}
		}
	}
	return cipherCodes
}
