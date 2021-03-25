package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/gorilla/mux"
	"github.com/pmylund/go-cache"
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

func validatePublicKeys(host string, conn *tls.Conn, spec *APISpec) bool {
	certLog.Debug("Checking certificate public key for host:", host)

	whitelist := getPinnedPublicKeys(host, spec)
	if len(whitelist) == 0 {
		return true
	}

	isValid := false

	state := conn.ConnectionState()
	for _, peercert := range state.PeerCertificates {
		der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		if err != nil {
			continue
		}
		fingerprint := certs.HexSHA256(der)

		for _, w := range whitelist {
			if w == fingerprint {
				isValid = true
				break
			}
		}
	}

	return isValid
}

func validateCommonName(host string, cert *x509.Certificate) error {
	certLog.Debug("Checking certificate CommonName for host :", host)

	if cert.Subject.CommonName != host {
		return errors.New("certificate had CN " + cert.Subject.CommonName + "expected " + host)
	}

	return nil
}

func customDialTLSCheck(spec *APISpec, tc *tls.Config) func(network, addr string) (net.Conn, error) {
	var checkPinnedKeys, checkCommonName bool

	if (spec != nil && len(spec.PinnedPublicKeys) != 0) || len(config.Global().Security.PinnedPublicKeys) != 0 {
		checkPinnedKeys = true
	}

	if (spec != nil && spec.Proxy.Transport.SSLForceCommonNameCheck) || config.Global().SSLForceCommonNameCheck {
		checkCommonName = true
	}

	if !checkCommonName && !checkPinnedKeys {
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

		if checkPinnedKeys {
			isValid := validatePublicKeys(host, c, spec)
			if !isValid {
				return nil, errors.New("https://" + host + " certificate public key pinning error. Public keys do not match.")
			}
		}

		if checkCommonName {
			state := c.ConnectionState()
			leafCert := state.PeerCertificates[0]
			err := validateCommonName(host, leafCert)
			if err != nil {
				return nil, err
			}
		}

		return c, nil
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

var tlsConfigCache = cache.New(60*time.Second, 60*time.Minute)

var tlsConfigMu sync.Mutex

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

	listenPortStr := strconv.Itoa(listenPort)

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if config, found := tlsConfigCache.Get(hello.ServerName + listenPortStr); found {
			return config.(*tls.Config).Clone(), nil
		}

		newConfig := baseConfig.Clone()

		// Avoiding Race
		newConfig.Certificates = []tls.Certificate{}
		for _, cert := range baseConfig.Certificates {
			newConfig.Certificates = append(newConfig.Certificates, cert)
		}
		newConfig.BuildNameToCertificate()
		for name, cert := range certNameMap {
			newConfig.NameToCertificate[name] = cert
		}

		isControlAPI := (listenPort != 0 && config.Global().ControlAPIPort == listenPort) || (config.Global().ControlAPIHostname == hello.ServerName)

		if isControlAPI && config.Global().Security.ControlAPIUseMutualTLS {
			newConfig.ClientAuth = tls.RequireAndVerifyClientCert
			newConfig.ClientCAs = CertificateManager.CertPool(config.Global().Security.Certificates.ControlAPI)

			tlsConfigCache.Set(hello.ServerName, newConfig, cache.DefaultExpiration)
			return newConfig, nil
		}

		apisMu.RLock()
		defer apisMu.RUnlock()

		newConfig.ClientCAs = x509.NewCertPool()

		domainRequireCert := map[string]tls.ClientAuthType{}
		for _, spec := range apiSpecs {
			switch {
			case spec.UseMutualTLSAuth:
				if domainRequireCert[spec.Domain] == 0 {
					// Require verification only if there is a single known domain for TLS auth, otherwise use previous value
					domainRequireCert[spec.Domain] = tls.RequireAndVerifyClientCert
				} else if domainRequireCert[spec.Domain] != tls.RequireAndVerifyClientCert {
					// If we have another API on this domain, which is not mutual tls enabled, just ask for cert
					domainRequireCert[spec.Domain] = tls.RequestClientCert
				}

				// If current domain match or empty, whitelist client certificates
				if spec.Domain == "" || spec.Domain == hello.ServerName {
					certIDs := append(spec.ClientCertificates, config.Global().Security.Certificates.API...)

					for _, cert := range CertificateManager.List(certIDs, certs.CertificatePublic) {
						if cert != nil {
							newConfig.ClientCAs.AddCert(cert.Leaf)
						}
					}
				}
			case spec.AuthConfigs[authTokenType].UseCertificate:
				// Dynamic certificate check required, falling back to HTTP level check
				// TODO: Change to VerifyPeerCertificate hook instead, when possible
				if domainRequireCert[spec.Domain] < tls.RequestClientCert {
					domainRequireCert[spec.Domain] = tls.RequestClientCert
				}
			default:
				// For APIs which do not use certificates, indicate that there is API for such domain already
				if domainRequireCert[spec.Domain] <= 0 {
					domainRequireCert[spec.Domain] = -1
				} else {
					domainRequireCert[spec.Domain] = tls.RequestClientCert
				}
			}

			// Dynamically add API specific certificates
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

		newConfig.ClientAuth = tls.NoClientCert

		for key, clientAuth := range domainRequireCert {
			req := http.Request{Host: hello.ServerName, URL: &url.URL{}}
			if mux.NewRouter().Host(key).Match(&req, &mux.RouteMatch{}) {
				newConfig.ClientAuth = clientAuth
				break
			}
		}

		if newConfig.ClientAuth == tls.NoClientCert {
			newConfig.ClientAuth = domainRequireCert[""]
		}

		// Cache the config
		tlsConfigCache.Set(hello.ServerName+listenPortStr, newConfig, cache.DefaultExpiration)
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
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" && len(certID) >= sha256.Size*2 {
			orgID = certID[:len(certID)-sha256.Size*2]
		}
		CertificateManager.Delete(certID, orgID)
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
