package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/cache"
	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	tyklog "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	cacheDefaultTTL    = 300 // 5 minutes.
	cacheCleanInterval = 600 // 10 minutes.

	// MDCB retry configuration for certificate loading during startup.
	//
	// When the gateway starts with MDCB configured, it enters emergency mode until the
	// RPC connection is established. During this period, certificate fetches from MDCB
	// will fail with ErrMDCBConnectionLost. These constants control the retry behavior:
	//
	// DefaultRPCCertFetchMaxElapsedTime: Maximum time to wait for MDCB to become ready (30 seconds)
	//   - If MDCB doesn't respond within this window, we give up and fall back to local files
	//   - This prevents indefinite blocking during gateway startup
	//
	// DefaultRPCCertFetchInitialInterval: Starting delay for exponential backoff (100ms)
	//   - First retry happens after 100ms
	//   - Each subsequent retry doubles: 100ms → 200ms → 400ms → 800ms → 1600ms → 2000ms (capped)
	//
	// DefaultRPCCertFetchMaxInterval: Maximum delay between retry attempts (2 seconds)
	//   - Caps exponential growth to prevent excessively long waits
	//   - Ensures we check MDCB at least every 2 seconds
	DefaultRPCCertFetchMaxElapsedTime  = 30 * time.Second
	DefaultRPCCertFetchInitialInterval = 100 * time.Millisecond
	DefaultRPCCertFetchMaxInterval     = 2 * time.Second

	// DefaultRPCCertFetchRetryEnabled: Enable retry by default (true)
	DefaultRPCCertFetchRetryEnabled = true

	// DefaultRPCCertFetchMaxRetries: Maximum number of retry attempts (5)
	//   - 0 means unlimited (time-based only)
	//   - Default of 5 provides reasonable retry attempts with exponential backoff
	DefaultRPCCertFetchMaxRetries = 5

	// embeddedPEMCacheKeyPrefix namespaces the in-process cache entries for
	// inline PEM input passed to List(). The prefix contains "-" which
	// disqualifies it from being a (hex-only) SHA256 cert ID, and is long
	// enough that an operator-supplied org ID cannot accidentally generate a
	// collision when prepended to a cert ID inside Add().
	embeddedPEMCacheKeyPrefix = "embedded-pem-"
)

var (
	CertManagerLogPrefix = "cert_storage"
)

var (
	GenCertificate       = tykcrypto.GenCertificate
	GenServerCertificate = tykcrypto.GenServerCertificate
	HexSHA256            = tykcrypto.HexSHA256
)

//go:generate mockgen -destination=./mock/mock.go -package=mock . CertificateManager

type CertificateManager interface {
	List(certIDs []string, mode CertificateType) (out []*tls.Certificate)
	ListPublicKeys(keyIDs []string) (out []string)
	ListRawPublicKey(keyID string) (out interface{})
	ListAllIds(prefix string) (out []string)
	GetRaw(certID string) (string, error)
	Add(certData []byte, orgID string) (string, error)
	Delete(certID string, orgID string)
	CertPool(certIDs []string) *x509.CertPool
	FlushCache()
	CertificateManagerIdGetter
}

type CertificateManagerIdGetter interface {
	GetId(certData []byte) (id string, err error)
}

type certificateManager struct {
	IdGetter
	storage                  StorageHandler
	logger                   *logrus.Entry
	cache                    cache.Repository
	secret                   string
	migrateCertList          bool
	certFetchMaxElapsedTime  time.Duration
	certFetchInitialInterval time.Duration
	certFetchMaxInterval     time.Duration
	certFetchRetryEnabled    bool
	certFetchMaxRetries      int
}

// CertificateManagerOption is a functional option for configuring certificate manager.
type CertificateManagerOption func(*certificateManager)

// WithRetryEnabled enables or disables retry logic for MDCB certificate fetching.
func WithRetryEnabled(enabled bool) CertificateManagerOption {
	return func(cm *certificateManager) {
		cm.certFetchRetryEnabled = enabled
	}
}

// WithMaxRetries sets the maximum number of retry attempts (0 = unlimited, time-based only).
func WithMaxRetries(maxRetries int) CertificateManagerOption {
	return func(cm *certificateManager) {
		cm.certFetchMaxRetries = maxRetries
	}
}

// WithBackoffIntervals configures the exponential backoff intervals.
func WithBackoffIntervals(maxElapsed, initial, max time.Duration) CertificateManagerOption {
	return func(cm *certificateManager) {
		if maxElapsed > 0 {
			cm.certFetchMaxElapsedTime = maxElapsed
		}
		if initial > 0 {
			cm.certFetchInitialInterval = initial
		}
		if max > 0 {
			cm.certFetchMaxInterval = max
		}
	}
}

type StorageHandler interface {
	storage.GetKeyHandler
	storage.SetKeyHandler
	storage.GetKeysHandler
	storage.RemoveFromListHandler
	storage.AppendToSetHandler
	storage.ExistsHandler
	storage.GetListRangeHandler
	storage.DeleteKeyHandler
	storage.DeleteScanMatchHandler
}

// NewCertificateManager creates a certificate manager with optional retry configuration.
// Maintains backward compatibility: calling without options uses defaults.
//
// Example with defaults (backward compatible):
//
//	cm := NewCertificateManager(storage, secret, logger, true)
//
// Example with custom retry config:
//
//	cm := NewCertificateManager(storage, secret, logger, true,
//	    WithRetryEnabled(true),
//	    WithMaxRetries(10),
//	    WithBackoffIntervals(60*time.Second, 200*time.Millisecond, 5*time.Second))
func NewCertificateManager(storageHandler StorageHandler, secret string, logger *tyklog.Logger, migrateCertList bool, opts ...CertificateManagerOption) *certificateManager {
	if logger == nil {
		logger = tyklog.Get()
	}

	cm := &certificateManager{
		IdGetter:                 NewIdGetter(secret),
		storage:                  storageHandler,
		logger:                   logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix}),
		cache:                    cache.New(cacheDefaultTTL, cacheCleanInterval),
		secret:                   secret,
		migrateCertList:          migrateCertList,
		certFetchMaxElapsedTime:  DefaultRPCCertFetchMaxElapsedTime,
		certFetchInitialInterval: DefaultRPCCertFetchInitialInterval,
		certFetchMaxInterval:     DefaultRPCCertFetchMaxInterval,
		certFetchRetryEnabled:    DefaultRPCCertFetchRetryEnabled,
		certFetchMaxRetries:      DefaultRPCCertFetchMaxRetries,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(cm)
	}

	return cm
}

func getOrgFromKeyID(key, certID string) string {
	orgId := strings.ReplaceAll(key, "raw-", "")
	orgId = strings.ReplaceAll(orgId, certID, "")
	return orgId
}

func NewSlaveCertManager(localStorage, rpcStorage storage.Handler, secret string, logger tyklog.Logger, migrateCertList bool, opts ...CertificateManagerOption) *certificateManager {
	if logger == nil {
		logger = tyklog.Get()
	}
	log := logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix})

	cm := &certificateManager{
		logger:                   log,
		cache:                    cache.New(cacheDefaultTTL, cacheCleanInterval),
		secret:                   secret,
		migrateCertList:          migrateCertList,
		certFetchMaxElapsedTime:  DefaultRPCCertFetchMaxElapsedTime,
		certFetchInitialInterval: DefaultRPCCertFetchInitialInterval,
		certFetchMaxInterval:     DefaultRPCCertFetchMaxInterval,
		certFetchRetryEnabled:    DefaultRPCCertFetchRetryEnabled,
		certFetchMaxRetries:      DefaultRPCCertFetchMaxRetries,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(cm)
	}

	callbackOnPullCertFromRPC := func(key, val string) error {
		// calculate the orgId from the keyId
		certID, _, _ := GetCertIDAndChainPEM([]byte(val), "")
		orgID := getOrgFromKeyID(key, certID)
		// save the cert in local redis
		_, err := cm.Add([]byte(val), orgID)
		return err
	}

	mdcbStorage := storage.NewMdcbStorage(localStorage, rpcStorage, log, callbackOnPullCertFromRPC)
	cm.storage = mdcbStorage
	return cm
}

// Extracted from: https://golang.org/src/crypto/tls/tls.go
//
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func isSHA256(value string) bool {
	// check if hex encoded
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}

	return true
}

// IsPEMContent reports whether the supplied string is an inline PEM block
// rather than a SHA256 certificate ID or a filesystem path. The check is
// intentionally permissive (substring rather than HasPrefix) so that values
// delivered via secret-store substitution — which often arrive with leading
// whitespace, BOM bytes, or YAML folding artefacts — are still recognised.
// pem.Decode performs the strict structural validation downstream, so any
// false positives here surface as clear parse errors, not silent failures.
//
// SHA256 IDs (hex-only) and POSIX file paths in practice never contain the
// "-----BEGIN " sentinel, so the three cert-source modes remain unambiguous.
//
// Exported so that callers outside this package (e.g. certUsageTracker in the
// gateway) can opt out of treating embedded PEM strings as cert IDs.
func IsPEMContent(value string) bool {
	return strings.Contains(value, "-----BEGIN ")
}

func ParsePEM(data []byte, secret string) ([]*pem.Block, error) {
	var pemBlocks []*pem.Block

	for {
		var block *pem.Block
		block, data = pem.Decode(data)

		if block == nil {
			break
		}

		if x509.IsEncryptedPEMBlock(block) {
			var err error
			block.Bytes, err = x509.DecryptPEMBlock(block, []byte(secret))
			block.Headers = nil
			block.Type = strings.Replace(block.Type, "ENCRYPTED ", "", 1)

			if err != nil {
				return nil, err
			}
		}

		pemBlocks = append(pemBlocks, block)
	}

	return pemBlocks, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func ParsePEMCertificate(data []byte, secret string) (*tls.Certificate, error) {
	var cert tls.Certificate

	blocks, err := ParsePEM(data, secret)
	if err != nil {
		return nil, err
	}

	var certID string

	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			certID = tykcrypto.HexSHA256(block.Bytes)
			cert.Certificate = append(cert.Certificate, block.Bytes)
			continue
		}

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			continue
		}

		if block.Type == "PUBLIC KEY" {
			// Create a dummny cert just for listing purpose
			cert.Certificate = append(cert.Certificate, block.Bytes)
			cert.Leaf = tykcrypto.PrefixPublicKeyCommonName(block.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("Can't find CERTIFICATE block")
	}

	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])

		if err != nil {
			return nil, err
		}
	}

	// Cache certificate fingerprint
	cert.Leaf.Extensions = append([]pkix.Extension{{
		Value: []byte(certID),
	}}, cert.Leaf.Extensions...)

	return &cert, nil
}

type CertificateType int

const (
	CertificatePrivate CertificateType = iota
	CertificatePublic
	CertificateAny
)

func isPrivateKeyEmpty(cert *tls.Certificate) bool {
	switch priv := cert.PrivateKey.(type) {
	default:
		if priv == nil {
			return true
		}
	}

	return false
}

func isCertCanBeListed(cert *tls.Certificate, mode CertificateType) bool {
	switch mode {
	case CertificatePrivate:
		return !isPrivateKeyEmpty(cert)
	case CertificateAny:
		return true
	}

	return true
}

type CertificateBasics struct {
	ID            string    `json:"id"`
	IssuerCN      string    `json:"issuer_cn"`
	SubjectCN     string    `json:"subject_cn"`
	DNSNames      []string  `json:"dns_names"`
	HasPrivateKey bool      `json:"has_private"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsCA          bool      `json:"is_ca"`
}

func ExtractCertificateBasics(cert *tls.Certificate, certID string) *CertificateBasics {
	return &CertificateBasics{
		ID:            certID,
		IssuerCN:      cert.Leaf.Issuer.CommonName,
		SubjectCN:     cert.Leaf.Subject.CommonName,
		DNSNames:      cert.Leaf.DNSNames,
		HasPrivateKey: !isPrivateKeyEmpty(cert),
		NotAfter:      cert.Leaf.NotAfter,
		NotBefore:     cert.Leaf.NotBefore,
		IsCA:          cert.Leaf.IsCA,
	}
}

type CertificateMeta struct {
	ID            string    `json:"id"`
	Fingerprint   string    `json:"fingerprint"`
	HasPrivateKey bool      `json:"has_private"`
	Issuer        pkix.Name `json:"issuer,omitempty"`
	Subject       pkix.Name `json:"subject,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	IsCA          bool      `json:"is_ca"`
}

// ToCertificateBasics converts a CertificateMeta to a CertificateBasics struct.
func (cm *CertificateMeta) ToCertificateBasics() *CertificateBasics {
	return &CertificateBasics{
		ID:            cm.ID,
		IssuerCN:      cm.Issuer.CommonName,
		SubjectCN:     cm.Subject.CommonName,
		DNSNames:      cm.DNSNames,
		HasPrivateKey: cm.HasPrivateKey,
		NotBefore:     cm.NotBefore,
		NotAfter:      cm.NotAfter,
		IsCA:          cm.IsCA,
	}
}

func ExtractCertificateMeta(cert *tls.Certificate, certID string) *CertificateMeta {
	return &CertificateMeta{
		ID:            certID,
		Fingerprint:   string(cert.Leaf.Extensions[0].Value),
		HasPrivateKey: !isPrivateKeyEmpty(cert),
		Issuer:        cert.Leaf.Issuer,
		Subject:       cert.Leaf.Subject,
		NotBefore:     cert.Leaf.NotBefore,
		NotAfter:      cert.Leaf.NotAfter,
		DNSNames:      cert.Leaf.DNSNames,
		IsCA:          cert.Leaf.IsCA,
	}
}

func GetCertIDAndChainPEM(certData []byte, secret string) (string, []byte, error) {
	var keyPEM, keyRaw []byte
	var publicKeyPem []byte
	var certBlocks [][]byte
	var certID string
	var certChainPEM []byte

	rest := certData

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			if len(keyRaw) > 0 {
				err := errors.New("Found multiple private keys")
				return certID, certChainPEM, err
			}

			keyRaw = block.Bytes
			keyPEM = pem.EncodeToMemory(block)
		} else if block.Type == "CERTIFICATE" {

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certID, certChainPEM, err
			}

			if cert.NotAfter.Before(time.Now()) {
				return certID, certChainPEM, errors.New("certificate is expired")
			}

			certBlocks = append(certBlocks, pem.EncodeToMemory(block))
		} else if block.Type == "PUBLIC KEY" {
			publicKeyPem = pem.EncodeToMemory(block)
		}
	}

	certChainPEM = bytes.Join(certBlocks, []byte("\n"))

	if len(certChainPEM) == 0 {
		if len(publicKeyPem) == 0 {
			err := errors.New("Failed to decode certificate. It should be PEM encoded.")
			return certID, certChainPEM, err
		} else {
			certChainPEM = publicKeyPem
		}
	} else if len(publicKeyPem) > 0 {
		err := errors.New("Public keys can't be combined with certificates")
		return certID, certChainPEM, err
	}

	// Found private key, check if it match the certificate
	if len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(certChainPEM, keyPEM)
		if err != nil {
			return certID, certChainPEM, err
		}

		// Encrypt private key and append it to the chain
		encryptedKeyPEMBlock, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", keyRaw, []byte(secret), x509.PEMCipherAES256)
		if err != nil {
			return certID, certChainPEM, err
		}

		certChainPEM = append(certChainPEM, []byte("\n")...)
		certChainPEM = append(certChainPEM, pem.EncodeToMemory(encryptedKeyPEMBlock)...)

		certID = tykcrypto.HexSHA256(cert.Certificate[0])
	} else if len(publicKeyPem) > 0 {
		publicKey, _ := pem.Decode(publicKeyPem)
		certID = tykcrypto.HexSHA256(publicKey.Bytes)
	} else {
		// Get first cert
		certRaw, _ := pem.Decode(certChainPEM)
		cert, err := x509.ParseCertificate(certRaw.Bytes)
		if err != nil {
			err := errors.New("Error while parsing certificate: " + err.Error())
			return certID, certChainPEM, err
		}

		certID = tykcrypto.HexSHA256(cert.Raw)
	}
	return certID, certChainPEM, nil
}

// fetchCertificateWithRetry retrieves a certificate from storage with optional retry support.
func (c *certificateManager) fetchCertificateWithRetry(id string, sharedBackoff backoff.BackOff) (string, error) {
	c.logger.WithFields(logrus.Fields{
		"cert_id":       id,
		"retry_enabled": c.certFetchRetryEnabled,
	}).Debug("Certificate fetch starting")

	// Early return: retry disabled
	if !c.certFetchRetryEnabled {
		c.logger.WithField("cert_id", id).Debug("Using non-retry path for certificate fetch")
		return c.storage.GetKey("raw-" + id)
	}

	// Retry enabled - use shared exponential backoff
	var val string
	var err error
	attemptCount := 0

	operation := func() error {
		attemptCount++
		logFields := logrus.Fields{"cert_id": id}

		if attemptCount == 1 {
			c.logger.WithFields(logFields).Debug("Fetching certificate from MDCB (retry enabled)")
		} else {
			logFields["attempt"] = attemptCount
			c.logger.WithFields(logFields).Debug("Retrying certificate fetch from MDCB")
		}

		val, err = c.storage.GetKey("raw-" + id)

		if errors.Is(err, storage.ErrMDCBConnectionLost) {
			c.logger.WithField("cert_id", id).Debug("Certificate fetch failed (MDCB not ready), will retry")
			return err // Retryable error
		}

		if err == nil {
			logFields["attempt"] = attemptCount
			c.logger.WithFields(logFields).Debug("Certificate fetched successfully from MDCB")
		}

		return nil // Success or non-retryable error
	}

	if retryErr := backoff.Retry(operation, sharedBackoff); retryErr != nil {
		if errors.Is(err, storage.ErrMDCBConnectionLost) {
			c.logger.WithField("cert_id", id).Warn("Timeout waiting for MDCB connection for certificate")
		}
	}

	return val, err
}

// appendEmbeddedPEM resolves a single inline-PEM cert ID, caches it under a
// content-derived key, and appends it (or nil on parse failure) to out.
//
// The cache prefix isolates these entries from SHA256-keyed Redis cert IDs
// (`embedded-pem-` contains a dash, which never appears in hex). We never
// persist embedded PEMs into the underlying storage: they are ephemeral
// content supplied by the API definition, or, in the future, by a
// secret-store substitution layer.
func (c *certificateManager) appendEmbeddedPEM(id string, mode CertificateType, out *[]*tls.Certificate) {
	rawCert := []byte(strings.TrimSpace(id))
	cacheKey := embeddedPEMCacheKeyPrefix + tykcrypto.HexSHA256(rawCert)

	if cached, found := c.cache.Get(cacheKey); found {
		if cert, ok := cached.(*tls.Certificate); ok && isCertCanBeListed(cert, mode) {
			*out = append(*out, cert)
		}
		return
	}

	parsedCert, parseErr := ParsePEMCertificate(rawCert, c.secret)
	if parseErr != nil {
		// Fallback: the input may be a PEM whose line breaks were collapsed
		// into spaces by a copy-paste into a single-line field (a common
		// Dashboard/secret-store mishap). Repair the formatting and retry
		// once before giving up.
		if repaired, ok := normalizeCollapsedPEM(rawCert); ok {
			if cert, retryErr := ParsePEMCertificate(repaired, c.secret); retryErr == nil {
				c.logger.Warn("Embedded PEM had non-canonical line formatting; normalized successfully. Please supply PEM with real line breaks (\\n).")
				parsedCert, parseErr = cert, nil
			}
		}
	}
	if parseErr != nil {
		// Never log the PEM body — it may contain a private key.
		c.logger.WithError(parseErr).Error("Error parsing embedded PEM certificate")
		*out = append(*out, nil)
		return
	}

	c.cache.Set(cacheKey, parsedCert, cache.DefaultExpiration)
	if isCertCanBeListed(parsedCert, mode) {
		*out = append(*out, parsedCert)
	}
}

// pemBlockRe matches a single PEM block whose internal line breaks may have
// been collapsed into spaces. The body group is non-greedy so multiple blocks
// (e.g. a certificate followed by its private key) are matched individually.
var pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]+?)-----(.*?)-----END [A-Z0-9 ]+?-----`)

// normalizeCollapsedPEM rebuilds a canonical PEM document from input whose line
// breaks were flattened into spaces (or other whitespace). For each block it
// strips all intra-body whitespace and re-wraps the base64 payload at 64
// columns with the BEGIN/END markers on their own lines.
//
// It returns ok=false when the input contains no recognisable PEM block, so the
// caller can preserve the original parse error. This runs only as a fallback
// after a normal parse fails, so well-formed input is never reshaped. Encrypted
// PEM blocks (which carry `Proc-Type`/`DEK-Info` headers) are not faithfully
// reproduced by this pass, but those parse correctly on the first attempt and
// therefore never reach this code; a genuinely malformed block simply fails the
// retry parse and yields the same nil as before.
func normalizeCollapsedPEM(data []byte) ([]byte, bool) {
	matches := pemBlockRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil, false
	}

	var out bytes.Buffer
	for _, m := range matches {
		blockType := string(m[1])
		body := strings.Join(strings.Fields(string(m[2])), "")

		out.WriteString("-----BEGIN " + blockType + "-----\n")
		for i := 0; i < len(body); i += 64 {
			end := i + 64
			if end > len(body) {
				end = len(body)
			}
			out.WriteString(body[i:end])
			out.WriteByte('\n')
		}
		out.WriteString("-----END " + blockType + "-----\n")
	}
	return out.Bytes(), true
}

func (c *certificateManager) List(certIDs []string, mode CertificateType) (out []*tls.Certificate) {
	var cert *tls.Certificate
	var rawCert []byte

	// Create backoff strategy once for all certificates in this List() call.
	// This prevents exponential delay multiplication when loading multiple certificates.
	// Without this, 100 certificates × 30s timeout = 50+ minutes startup delay!
	var sharedBackoff backoff.BackOff
	if c.certFetchRetryEnabled {
		expBackoff := backoff.NewExponentialBackOff()
		expBackoff.MaxElapsedTime = c.certFetchMaxElapsedTime
		expBackoff.InitialInterval = c.certFetchInitialInterval
		expBackoff.MaxInterval = c.certFetchMaxInterval
		expBackoff.Multiplier = 2.0

		// Apply max retries limit if configured (0 = unlimited, time-based only)
		if c.certFetchMaxRetries > 0 {
			sharedBackoff = backoff.WithMaxRetries(expBackoff, uint64(c.certFetchMaxRetries))
		} else {
			sharedBackoff = expBackoff
		}
	}

	for _, id := range certIDs {
		// Embedded PEM branch: when the id is a literal PEM block (rather than
		// a SHA256 cert ID or filesystem path), parse it in-process and cache
		// under a content-derived key. We deliberately do NOT persist embedded
		// PEMs into the underlying storage — they are treated as ephemeral
		// content supplied by the API definition (or, in the future, by a
		// secret-store substitution layer).
		if IsPEMContent(id) {
			c.appendEmbeddedPEM(id, mode, &out)
			continue
		}

		if cert, found := c.cache.Get(id); found {
			if isCertCanBeListed(cert.(*tls.Certificate), mode) {
				out = append(out, cert.(*tls.Certificate))
			}
			continue
		}

		// Fetch certificate from storage with optional retry support
		val, err := c.fetchCertificateWithRetry(id, sharedBackoff)
		// fallback to file
		if err != nil {
			// Try read from file
			rawCert, err = ioutil.ReadFile(id)
			if err != nil {
				c.logger.Warn("Can't retrieve certificate:", id, err)
				out = append(out, nil)
				continue
			}
		} else {
			rawCert = []byte(val)
		}

		cert, err = ParsePEMCertificate(rawCert, c.secret)
		if err != nil {
			c.logger.Error("Error while parsing certificate: ", id, " ", err)
			c.logger.Debug("Failed certificate: ", string(rawCert))
			out = append(out, nil)
			continue
		}

		c.cache.Set(id, cert, cache.DefaultExpiration)

		if isCertCanBeListed(cert, mode) {
			out = append(out, cert)
		}
	}

	return out
}

// Returns list of fingerprints.
//
// publicKeyCacheKey derives the in-process cache key for a pinned-key
// reference. Inline PEM is hashed (mirroring embeddedPEMCacheKeyPrefix used by
// List()) so the key stays bounded and matches on the trimmed content; SHA256
// IDs and file paths are short and used verbatim.
func publicKeyCacheKey(id string) string {
	if IsPEMContent(id) {
		return embeddedPEMCacheKeyPrefix + "pub-" + tykcrypto.HexSHA256([]byte(strings.TrimSpace(id)))
	}
	return "pub-" + id
}

// decodePublicKeyBlock decodes the first PEM block from rawKey. If the input
// has been whitespace-collapsed (e.g. pasted into a single-line field), it is
// normalised and retried once, matching the tolerance of appendEmbeddedPEM.
func decodePublicKeyBlock(rawKey []byte) *pem.Block {
	if block, _ := pem.Decode(rawKey); block != nil {
		return block
	}
	if repaired, ok := normalizeCollapsedPEM(rawKey); ok {
		if block, _ := pem.Decode(repaired); block != nil {
			return block
		}
	}
	return nil
}

// ListPublicKeys resolves pinned-public-key references to their fingerprints.
// A reference is one of: a SHA256 ID (Redis-backed), an inline PEM public key
// (embedded content, e.g. substituted from a secret store), or a filesystem
// path. Inline PEM is detected by content sniffing and decoded in memory,
// mirroring the embedded-PEM branch in List().
func (c *certificateManager) ListPublicKeys(keyIDs []string) (out []string) {
	var rawKey []byte
	var err error

	for _, id := range keyIDs {
		cacheKey := publicKeyCacheKey(id)
		if fingerprint, found := c.cache.Get(cacheKey); found {
			out = append(out, fingerprint.(string))
			continue
		}

		switch {
		case isSHA256(id):
			var val string
			val, err := c.storage.GetKey("raw-" + id)
			if err != nil {
				c.logger.Warn("Can't retrieve public key from Redis:", id, err)
				out = append(out, "")
				continue
			}
			rawKey = []byte(val)
		case IsPEMContent(id):
			rawKey = []byte(strings.TrimSpace(id))
		default:
			rawKey, err = ioutil.ReadFile(id)
			if err != nil {
				c.logger.Error("Error while reading public key from file:", id, err)
				out = append(out, "")
				continue
			}
		}

		block := decodePublicKeyBlock(rawKey)
		if block == nil {
			c.logger.Error("Can't parse public key:", id)
			out = append(out, "")
			continue
		}

		fingerprint := tykcrypto.HexSHA256(block.Bytes)
		c.cache.Set(cacheKey, fingerprint, cache.DefaultExpiration)
		out = append(out, fingerprint)
	}

	return out
}

// Returns list of fingerprints
func (c *certificateManager) ListRawPublicKey(keyID string) (out interface{}) {
	var rawKey []byte
	var err error

	switch {
	case isSHA256(keyID):
		var val string
		val, err := c.storage.GetKey("raw-" + keyID)
		if err != nil {
			c.logger.Warn("Can't retrieve public key from Redis:", keyID, err)
			return nil
		}
		rawKey = []byte(val)
	case IsPEMContent(keyID):
		rawKey = []byte(strings.TrimSpace(keyID))
	default:
		rawKey, err = ioutil.ReadFile(keyID)
		if err != nil {
			c.logger.Error("Error while reading public key from file:", keyID, err)
			return nil
		}
	}

	block := decodePublicKeyBlock(rawKey)
	if block == nil {
		c.logger.Error("Can't parse public key:", keyID)
		return nil
	}

	out, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		c.logger.Error("Error while parsing public key:", keyID, err)
		return nil
	}

	return out
}

func (c *certificateManager) ListAllIds(prefix string) (out []string) {
	indexKey := prefix + "-index"
	exists, _ := c.storage.Exists(indexKey)
	if !c.migrateCertList || (exists && prefix != "") {
		keys, _ := c.storage.GetListRange(indexKey, 0, -1)
		for _, key := range keys {
			out = append(out, strings.TrimPrefix(key, "raw-"))
		}
	} else {
		// If list is not exists, but migrated record exists, it means it just empty

		if _, err := c.storage.GetKey(indexKey + "-migrated"); err == nil {
			return out
		}

		keys := c.storage.GetKeys("raw-" + prefix + "*")

		for _, key := range keys {
			if prefix != "" {
				c.storage.AppendToSet(indexKey, key)
			}
			out = append(out, strings.TrimPrefix(key, "raw-"))
		}
	}
	c.storage.SetKey(indexKey+"-migrated", "1", 0)

	return out
}

// MaskCertID truncates certificate IDs for logging to prevent information leakage.
// Certificate IDs can be derived from API keys/auth tokens and should not be logged in clear text.
// Returns first 8 characters plus length for debugging while protecting sensitive data.
func MaskCertID(certID string) string {
	if len(certID) <= 8 {
		return certID
	}
	return certID[:8] + "***[len=" + strconv.Itoa(len(certID)) + "]"
}

func (c *certificateManager) GetRaw(certID string) (string, error) {
	return c.storage.GetKey("raw-" + certID)
}

func (c *certificateManager) Add(certData []byte, orgID string) (string, error) {

	certID, certChainPEM, err := GetCertIDAndChainPEM(certData, c.secret)
	if err != nil {
		c.logger.Error(err)
		return "", err
	}
	certID = orgID + certID

	if found, err := c.storage.Exists("raw-" + certID); err == nil && found {
		return "", errors.New("Certificate with " + certID + " id already exists")
	}

	if err := c.storage.SetKey("raw-"+certID, string(certChainPEM), 0); err != nil {
		c.logger.Error(err)
		return "", err
	}

	if orgID != "" {
		c.storage.AppendToSet(orgID+"-index", "raw-"+certID)
	}

	return certID, nil
}

func (c *certificateManager) Delete(certID string, orgID string) {

	if orgID != "" {
		c.storage.RemoveFromList(orgID+"-index", "raw-"+certID)
	}

	c.storage.DeleteKey("raw-" + certID)
	c.cache.Delete(certID)
}

func (c *certificateManager) CertPool(certIDs []string) *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range c.List(certIDs, CertificatePublic) {
		if cert != nil && !tykcrypto.IsPublicKey(cert) {
			tykcrypto.AddCACertificatesFromChainToPool(pool, cert)
		}
	}

	return pool
}

func (c *certificateManager) FlushCache() {
	c.cache.Flush()
}

func (c *certificateManager) flushStorage() {
	c.storage.DeleteScanMatch("*")
}

func NewIdGetter(secret string) IdGetter {
	return IdGetter{
		secret: secret,
	}
}

type IdGetter struct {
	secret string
}

func (c *IdGetter) GetId(certData []byte) (id string, err error) {
	certID, _, err := GetCertIDAndChainPEM(certData, c.secret)
	return certID, err
}
