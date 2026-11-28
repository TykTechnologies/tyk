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

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/crypto"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/internal/cache"
)

const ListDetailed = "detailed"

type APICertificateStatusMessage struct {
	CertID  string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type APIAllCertificates struct {
	CertIDs []string `json:"certs"`
}

type APIAllCertificateBasics struct {
	Certs []*certs.CertificateBasics `json:"certs"`
}

// Deprecated: use tls.CipherSuites() now
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

// getCertificateIDForHost returns the certificate ID that matches the given host from the provided certificate maps.
// It tries multiple matching patterns to find the best match:
// 1. Wildcard "*" - matches any host
// 2. Wildcard subdomain patterns with port - "*.example.com:8443"
// 3. Wildcard subdomain patterns without port - "*.example.com"
// 4. Exact hostname match with port - "api.example.com:8443"
// 5. Exact hostname match without port - "api.example.com"
//
// The function automatically handles hosts with ports by using net.SplitHostPort.
// Certificate maps are checked in order, with later maps taking precedence (allowing spec config to override global config).
func getCertificateIDForHost(host string, certMaps []map[string]string) string {
	var certID string

	// Strip port from host for certificate matching
	// If host is "example.com:8443", hostWithoutPort becomes "example.com"
	// If host has no port, hostWithoutPort equals host
	hostWithoutPort := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostWithoutPort = h
	}

	for _, m := range certMaps {
		if len(m) == 0 {
			continue
		}

		// Try wildcard match for any host
		if id, ok := m["*"]; ok {
			certID = id
		}

		// Try wildcard subdomain pattern matches
		hostParts := strings.SplitN(hostWithoutPort, ".", 2)
		if len(hostParts) > 1 {
			// Try pattern without port first (less specific)
			// e.g., "*.example.com" from config matches "api.example.com:8443" request
			hostPattern := "*." + hostParts[1]
			if id, ok := m[hostPattern]; ok {
				certID = id
			}

			// Try pattern with original host (includes port if present) - higher priority
			// e.g., "*.example.com:8443" from config matches "api.example.com:8443" request
			// More specific patterns (with port) override less specific patterns (without port)
			hostPartsWithPort := strings.SplitN(host, ".", 2)
			if len(hostPartsWithPort) > 1 {
				hostPatternWithPort := "*." + hostPartsWithPort[1]
				if id, ok := m[hostPatternWithPort]; ok {
					certID = id
				}
			}
		}

		// Try exact match without port first (most common case)
		// This ensures "example.com" config matches "example.com:8443" request
		if id, ok := m[hostWithoutPort]; ok {
			certID = id
		}

		// Try exact match with original host (higher priority, more specific)
		// This allows configs that include port to override more general configs
		if id, ok := m[host]; ok {
			certID = id
		}
	}

	return certID
}

func (gw *Gateway) getUpstreamCertificate(host string, spec *APISpec) (cert *tls.Certificate) {
	certMaps := []map[string]string{gw.GetConfig().Security.Certificates.Upstream}

	if spec != nil && !spec.UpstreamCertificatesDisabled && spec.UpstreamCertificates != nil {
		certMaps = append(certMaps, spec.UpstreamCertificates)
	}

	certID := getCertificateIDForHost(host, certMaps)
	if certID == "" {
		return nil
	}

	certs := gw.CertificateManager.List([]string{certID}, certs.CertificatePrivate)
	if len(certs) == 0 {
		return nil
	}

	return certs[0]
}

// errPublicKeyPinning is the error returned when an upstream certificate fails
// the pin check on the upstream-proxy path. The wording predates the linter rule
// and is kept so that existing log matching keeps working.
var errPublicKeyPinning = errors.New("Certificate public key pinning error. Public keys do not match.") //nolint:staticcheck // ST1005: existing message, kept unchanged

func (gw *Gateway) verifyPeerCertificatePinnedCheck(spec *APISpec, tlsConfig *tls.Config) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if !pinningEnabled(spec, gw.GetConfig()) {
		return nil
	}

	// Only the "*" pin can apply here: the callback is not told which host
	// it is verifying. Without one, keep standard verification.
	if hasHostPins(spec, gw.GetConfig()) {
		certLog.Warning("Certificate pinning: the upstream is reached through an HTTP proxy, so only the \"*\" pin is checked. Pins for specific domains are ignored.")
	}

	whitelist, pinned := gw.getPinnedPublicKeys("*", spec, gw.GetConfig())
	if !pinned {
		return nil
	}

	// A "*" pin with an empty value pins every host to nothing.
	if len(whitelist) == 0 {
		return func([][]byte, [][]*x509.Certificate) error {
			return errPublicKeyPinning
		}
	}

	tlsConfig.InsecureSkipVerify = true

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certLog.Debug("Checking certificate public key")

		for _, rawCert := range rawCerts {
			cert, _ := x509.ParseCertificate(rawCert)
			pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				continue
			}

			fingerprint := crypto.HexSHA256(pub)

			for _, w := range whitelist {
				if w == fingerprint {
					return nil
				}
			}
		}

		return errPublicKeyPinning
	}
}

// validatePublicKeys reports whether any certificate presented on conn has a
// public key in whitelist. An empty whitelist never matches.
func validatePublicKeys(host string, conn *tls.Conn, whitelist []string) bool {
	certLog.Debug("Checking certificate public key for host:", host)

	if len(whitelist) == 0 {
		return false
	}

	isValid := false

	state := conn.ConnectionState()
	for _, peercert := range state.PeerCertificates {
		der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		if err != nil {
			continue
		}
		fingerprint := crypto.HexSHA256(der)

		for _, w := range whitelist {
			if w == fingerprint {
				isValid = true
				break
			}
		}
	}

	return isValid
}

// pinningEnabled reports whether any pins apply to spec, from the API
// definition or from the gateway configuration.
func pinningEnabled(spec *APISpec, conf config.Config) bool {
	apiPins := spec != nil && !spec.CertificatePinningDisabled && len(spec.PinnedPublicKeys) != 0
	return apiPins || len(conf.Security.PinnedPublicKeys) != 0
}

// commonNameCheckEnabled reports whether the upstream certificate's common
// name must match the upstream host.
func commonNameCheckEnabled(spec *APISpec, conf config.Config) bool {
	return (spec != nil && spec.Proxy.Transport.SSLForceCommonNameCheck) || conf.SSLForceCommonNameCheck
}

// hostPinningError is the error returned when a directly dialed upstream fails
// the pin check.
func hostPinningError(host string) error {
	return errors.New("https://" + host + " certificate public key pinning error. Public keys do not match.")
}

// hostPins returns the fingerprints pinned for host. It returns none when host
// is not pinned, and an error when host is pinned with an empty value.
func (gw *Gateway) hostPins(host string, spec *APISpec) ([]string, error) {
	whitelist, pinned := gw.getPinnedPublicKeys(host, spec, gw.GetConfig())
	if pinned && len(whitelist) == 0 {
		return nil, hostPinningError(host)
	}

	return whitelist, nil
}

func validateCommonName(host string, cert *x509.Certificate) error {
	certLog.Debug("Checking certificate CommonName for host :", host)

	if cert.Subject.CommonName != host {
		return errors.New("certificate had CN " + cert.Subject.CommonName + "expected " + host)
	}

	return nil
}

func (gw *Gateway) customDialTLSCheck(spec *APISpec, tc *tls.Config) func(network, addr string) (net.Conn, error) {
	gwConfig := gw.GetConfig()
	checkPinnedKeys := pinningEnabled(spec, gwConfig)
	checkCommonName := commonNameCheckEnabled(spec, gwConfig)

	if !checkCommonName && !checkPinnedKeys {
		return nil
	}

	return func(network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		var whitelist []string
		if checkPinnedKeys {
			if whitelist, err = gw.hostPins(host, spec); err != nil {
				return nil, err
			}
		}

		clone := tc.Clone()

		// A pinned host is verified by its public key instead of its
		// certificate chain, so pinned self-signed upstreams keep working.
		// A host with no pin keeps the caller's verification setting.
		// The forced common name check still skips chain verification. That
		// is a separate issue, listed as out of scope in TT-18123.
		if len(whitelist) > 0 || checkCommonName {
			clone.InsecureSkipVerify = true
		}

		c, err := tls.Dial(network, addr, clone)
		if err != nil {
			// Return a nil interface, not a nil *tls.Conn wrapped in one.
			return nil, err
		}

		if len(whitelist) > 0 && !validatePublicKeys(host, c, whitelist) {
			_ = c.Close()
			return nil, hostPinningError(host)
		}

		if checkCommonName {
			if err := validateCommonName(host, c.ConnectionState().PeerCertificates[0]); err != nil {
				return nil, err
			}
		}

		return c, nil
	}
}

// getPinnedPublicKeys returns the public key fingerprints pinned for host and
// whether any pin entry matched host at all. A pin entry matches by exact host,
// by "*.<parent domain>", or by "*"; the API's pins take precedence over the
// gateway-wide pins, and an exact host over a wildcard over "*".
//
// configured is true when an entry matched, even if its value is empty or its
// key IDs resolve to no usable fingerprint. Callers use it to tell "this host
// is not pinned" apart from "this host is pinned but no key is available".
func (gw *Gateway) getPinnedPublicKeys(host string, spec *APISpec, conf config.Config) (fingerprints []string, configured bool) {
	var keyIDs string

	pinMaps := []map[string]string{conf.Security.PinnedPublicKeys}

	if spec != nil && !spec.CertificatePinningDisabled && spec.PinnedPublicKeys != nil {
		pinMaps = append(pinMaps, spec.PinnedPublicKeys)
	}

	for _, m := range pinMaps {
		if len(m) == 0 {
			continue
		}

		if id, ok := m["*"]; ok {
			keyIDs, configured = id, true
		}

		hostParts := strings.SplitN(host, ".", 2)
		if len(hostParts) > 1 {
			hostPattern := "*." + hostParts[1]

			if id, ok := m[hostPattern]; ok {
				keyIDs, configured = id, true
			}
		}

		if id, ok := m[host]; ok {
			keyIDs, configured = id, true
		}
	}

	if keyIDs == "" {
		return nil, configured
	}

	return gw.CertificateManager.ListPublicKeys(strings.Split(keyIDs, ",")), configured
}

// hasHostPins reports whether pinning applies to spec through a pin entry other
// than "*". Those entries are not checked when the upstream is reached through
// an HTTP proxy.
func hasHostPins(spec *APISpec, conf config.Config) bool {
	pinMaps := []map[string]string{conf.Security.PinnedPublicKeys}
	if spec != nil && !spec.CertificatePinningDisabled {
		pinMaps = append(pinMaps, spec.PinnedPublicKeys)
	}

	for _, m := range pinMaps {
		for domain := range m {
			if domain != "*" {
				return true
			}
		}
	}

	return false
}

// dummyGetCertificate needed because TLSConfig require setting Certificates array or GetCertificate function from start, even if it get overridden by `getTLSConfigForClient`
func dummyGetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

var tlsConfigCache = cache.New(60, 3600)

var tlsConfigMu sync.Mutex

func getClientValidator(helloInfo *tls.ClientHelloInfo, certPool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("x509: missing client certificate")
		}

		cert, certErr := x509.ParseCertificate(rawCerts[0])
		if certErr != nil {
			return certErr
		}

		opts := x509.VerifyOptions{
			Roots:         certPool,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		_, err := cert.Verify(opts)

		return err
	}
}

// logServerCertificateExpiry logs certificate expiry information for server certificates.
// It parses the certificate and logs a warning if expiring soon, or debug otherwise.
// The source parameter differentiates the certificate origin (e.g., "file" or "store").
func logServerCertificateExpiry(cert *tls.Certificate, threshold int, source string) {
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	daysUntilExpiry := int(time.Until(parsedCert.NotAfter).Hours() / 24)
	fields := log.WithField("cert_name", parsedCert.Subject.CommonName).
		WithField("expires_at", parsedCert.NotAfter).
		WithField("days_remaining", daysUntilExpiry)

	if daysUntilExpiry < threshold {
		if source == "store" {
			fields.Warn("Server certificate (from store) expiring soon")
		} else {
			fields.Warn("Server certificate expiring soon")
		}
	} else {
		if source == "store" {
			fields.Debug("Loaded server certificate from Certificate Store")
		} else {
			fields.Debug("Loaded server certificate")
		}
	}
}

func (gw *Gateway) getTLSConfigForClient(baseConfig *tls.Config, listenPort int) func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	gwConfig := gw.GetConfig()
	// Supporting legacy certificate configuration
	serverCerts := []tls.Certificate{}
	certNameMap := map[string]*tls.Certificate{}

	for _, certData := range gwConfig.HttpServerOptions.Certificates {
		cert, err := tls.LoadX509KeyPair(certData.CertFile, certData.KeyFile)
		if err != nil {
			log.Errorf("Server error: loadkeys: %s", err)
			continue
		}
		serverCerts = append(serverCerts, cert)
		certNameMap[certData.Name] = &cert
	}

	// Log file-based server certificate expiry info
	threshold := gwConfig.Security.CertificateExpiryMonitor.WarningThresholdDays
	for i := range serverCerts {
		logServerCertificateExpiry(&serverCerts[i], threshold, "file")
	}

	if len(gwConfig.HttpServerOptions.SSLCertificates) > 0 {
		var waitingRedisLog sync.Once
		// ensure that we are connected to redis
		for {
			if gw.StorageConnectionHandler.Connected() {
				break
			}

			waitingRedisLog.Do(func() {
				log.Warning("Redis is not ready. Waiting for a living connection")
			})
			time.Sleep(10 * time.Millisecond)
		}
	}
	sslCertificates := gw.CertificateManager.List(gwConfig.HttpServerOptions.SSLCertificates, certs.CertificatePrivate)
	for _, cert := range sslCertificates {
		if cert != nil {
			serverCerts = append(serverCerts, *cert)
		}
	}

	// Log Certificate Store server certificate expiry info
	for _, cert := range sslCertificates {
		if cert != nil {
			logServerCertificateExpiry(cert, threshold, "store")
		}
	}

	baseConfig.Certificates = serverCerts
	baseConfig.BuildNameToCertificate()

	for name, cert := range certNameMap {
		baseConfig.NameToCertificate[name] = cert
	}

	if len(baseConfig.CurvePreferences) == 0 {
		baseConfig.CurvePreferences = defaultCurvePreferences()
	}

	listenPortStr := strconv.Itoa(listenPort)

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if config, found := tlsConfigCache.Get(hello.ServerName + listenPortStr); found {
			return config.(*tls.Config).Clone(), nil
		}

		newConfig := baseConfig.Clone()
		if len(newConfig.CurvePreferences) == 0 {
			newConfig.CurvePreferences = defaultCurvePreferences()
		}

		// Avoiding Race
		newConfig.Certificates = []tls.Certificate{}
		for _, cert := range baseConfig.Certificates {
			newConfig.Certificates = append(newConfig.Certificates, cert)
		}
		newConfig.BuildNameToCertificate()
		for name, cert := range certNameMap {
			newConfig.NameToCertificate[name] = cert
		}

		// not ControlAPIHostname has been configured or the hostName is the same in the hello handshake
		isControlHostName := gwConfig.ControlAPIHostname == "" || (gwConfig.ControlAPIHostname == hello.ServerName)
		// target port is the same where control api lives
		isControlPort := (gwConfig.ControlAPIPort == 0 && listenPort == gwConfig.ListenPort) || (gwConfig.ControlAPIPort == listenPort && listenPort != 0)
		isControlAPI := isControlHostName && isControlPort

		if isControlAPI && gwConfig.Security.ControlAPIUseMutualTLS {
			newConfig.ClientAuth = tls.RequireAndVerifyClientCert
			newConfig.ClientCAs = gw.CertificateManager.CertPool(gwConfig.Security.Certificates.ControlAPI)

			tlsConfigCache.Set(hello.ServerName, newConfig, cache.DefaultExpiration)
			return newConfig, nil
		}

		gw.apisMu.RLock()
		defer gw.apisMu.RUnlock()

		newConfig.ClientCAs = x509.NewCertPool()
		domainRequireCert := map[string]tls.ClientAuthType{}

		directMTLSDomainMatch := false
		for _, spec := range gw.apiSpecs {
			if spec.UseMutualTLSAuth && spec.Domain == hello.ServerName {
				directMTLSDomainMatch = true
				break
			}
		}

		for _, spec := range gw.apiSpecs {
			// eliminate APIs which are not in the current port
			if !spec.isListeningOnPort(listenPort, &gwConfig) {
				continue
			}

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
				if (!directMTLSDomainMatch && spec.Domain == "") || spec.Domain == hello.ServerName {
					certIDs := append(spec.ClientCertificates, gwConfig.Security.Certificates.API...)

					clientCACerts := gw.CertificateManager.List(certIDs, certs.CertificatePublic)
					for _, cert := range clientCACerts {
						if cert != nil && !crypto.IsPublicKey(cert) {
							crypto.AddCACertificatesFromChainToPool(newConfig.ClientCAs, cert)
						}
					}
				}
			case spec.Auth.UseCertificate, spec.AuthConfigs[apidef.AuthTokenType].UseCertificate:
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
			if len(spec.Certificates) != 0 && !spec.DomainDisabled {
				apiSpecificCerts := gw.CertificateManager.List(spec.Certificates, certs.CertificatePrivate)
				for _, cert := range apiSpecificCerts {
					if cert == nil {
						continue
					}
					newConfig.Certificates = append(newConfig.Certificates, *cert)

					if len(cert.Leaf.Subject.CommonName) > 0 {
						newConfig.NameToCertificate[cert.Leaf.Subject.CommonName] = cert
					}
					for _, san := range cert.Leaf.DNSNames {
						newConfig.NameToCertificate[san] = cert
					}
				}
			}
		}

		if clientAuth, found := domainRequireCert[hello.ServerName]; found {
			newConfig.ClientAuth = clientAuth
		} else {
			newConfig.ClientAuth = tls.NoClientCert

			for domain, clientAuth := range domainRequireCert {
				isRegex := false
				for _, c := range domain {
					if c == '{' {
						isRegex = true
						break
					}
				}

				req := http.Request{Host: hello.ServerName, URL: &url.URL{}}
				if isRegex && mux.NewRouter().Host(domain).Match(&req, &mux.RouteMatch{}) {
					if clientAuth > newConfig.ClientAuth {
						newConfig.ClientAuth = clientAuth
					}

					if newConfig.ClientAuth == tls.RequireAndVerifyClientCert {
						break
					}
				}
			}
		}

		if newConfig.ClientAuth == tls.NoClientCert {
			newConfig.ClientAuth = domainRequireCert[""]
		}

		if gwConfig.HttpServerOptions.SkipClientCAAnnouncement {
			if newConfig.ClientAuth == tls.RequireAndVerifyClientCert {
				newConfig.VerifyPeerCertificate = getClientValidator(hello, newConfig.ClientCAs)
			}
			newConfig.ClientCAs = x509.NewCertPool()
			newConfig.ClientAuth = tls.RequestClientCert
		}

		if newConfig.ClientAuth == tls.RequireAndVerifyClientCert && isControlAPI && !gwConfig.Security.ControlAPIUseMutualTLS {

			newConfig.ClientAuth = tls.RequestClientCert
		}

		// Cache the config
		tlsConfigCache.Set(hello.ServerName+listenPortStr, newConfig, cache.DefaultExpiration)

		return newConfig, nil
	}
}

func (gw *Gateway) certHandler(w http.ResponseWriter, r *http.Request) {
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
		if certID, err = gw.CertificateManager.Add(content, orgID); err != nil {
			doJSONWrite(w, http.StatusForbidden, apiError(err.Error()))
			return
		}

		doJSONWrite(w, http.StatusOK, &APICertificateStatusMessage{certID, "ok", "Certificate added"})
	case "GET":
		if certID == "" {
			orgID := r.URL.Query().Get("org_id")
			mode := r.URL.Query().Get("mode")
			certIDs := gw.CertificateManager.ListAllIds(orgID)
			if mode == ListDetailed {
				var certificateBasics = make([]*certs.CertificateBasics, len(certIDs))
				certificates := gw.CertificateManager.List(certIDs, certs.CertificateAny)
				for ci, certificate := range certificates {
					certificateBasics[ci] = certs.ExtractCertificateBasics(certificate, certIDs[ci])
				}

				doJSONWrite(w, http.StatusOK, &APIAllCertificateBasics{Certs: certificateBasics})
				return
			}

			doJSONWrite(w, http.StatusOK, &APIAllCertificates{certIDs})
			return
		}

		certIDs := strings.Split(certID, ",")
		certificates := gw.CertificateManager.List(certIDs, certs.CertificateAny)

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
		gw.CertificateManager.Delete(certID, orgID)
		doJSONWrite(w, http.StatusOK, &apiStatusMessage{"ok", "removed"})
	}
}

func getCipherAliases(ciphers []string) (cipherCodes []uint16) {
	for _, v := range ciphers {
		id, err := crypto.ResolveCipher(v)
		if err != nil {
			log.Debugf("cipher %s not found; skipped", v)
			continue
		}
		cipherCodes = append(cipherCodes, id)
	}
	return cipherCodes
}

// maskCertID masks certificate ID for logging to avoid exposing sensitive data.
// Certificate IDs can be derived from API keys/auth tokens and should not be logged in clear text.
// Returns first 8 characters plus length for debugging while protecting sensitive data.
