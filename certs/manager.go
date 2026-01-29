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
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/cache"
	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	cacheDefaultTTL    = 300 // 5 minutes.
	cacheCleanInterval = 600 // 10 minutes.
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

// CertUsageTracker defines the interface for certificate requirement tracking
type CertUsageTracker interface {
	Required(certID string) bool
}

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
	SetRegistry(registry CertUsageTracker)
}

type certificateManager struct {
	storage         storage.Handler
	logger          *logrus.Entry
	cache           cache.Repository
	secret          string
	migrateCertList bool
	registry        CertUsageTracker
	selectiveSync   bool
}

func NewCertificateManager(storage storage.Handler, secret string, logger *logrus.Logger, migrateCertList bool) *certificateManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &certificateManager{
		storage:         storage,
		logger:          logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix}),
		cache:           cache.New(cacheDefaultTTL, cacheCleanInterval),
		secret:          secret,
		migrateCertList: migrateCertList,
	}
}

func getOrgFromKeyID(key, certID string) string {
	orgId := strings.ReplaceAll(key, "raw-", "")
	orgId = strings.ReplaceAll(orgId, certID, "")
	return orgId
}

func NewSlaveCertManager(localStorage, rpcStorage storage.Handler, secret string, logger *logrus.Logger, migrateCertList bool) *certificateManager {
	if logger == nil {
		logger = logrus.New()
	}
	log := logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix})

	cm := &certificateManager{
		logger:          log,
		cache:           cache.New(cacheDefaultTTL, cacheCleanInterval),
		secret:          secret,
		migrateCertList: migrateCertList,
	}

	callbackOnPullCertFromRPC := func(key, val string) error {
		// calculate the orgId from the keyId
		certID, _, _ := GetCertIDAndChainPEM([]byte(val), "")
		orgID := getOrgFromKeyID(key, certID)
		// save the cert in local redis
		_, err := cm.Add([]byte(val), orgID)
		return err
	}

	mdcbStorage := storage.NewMdcbStorage(localStorage, rpcStorage, log, callbackOnPullCertFromRPC, nil, nil)
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

func (c *certificateManager) List(certIDs []string, mode CertificateType) (out []*tls.Certificate) {
	var cert *tls.Certificate
	var rawCert []byte

	for _, id := range certIDs {
		if cert, found := c.cache.Get(id); found {
			if isCertCanBeListed(cert.(*tls.Certificate), mode) {
				out = append(out, cert.(*tls.Certificate))
			}
			continue
		}

		val, err := c.GetRaw(id)
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

// Returns list of fingerprints
func (c *certificateManager) ListPublicKeys(keyIDs []string) (out []string) {
	var rawKey []byte
	var err error

	for _, id := range keyIDs {
		if fingerprint, found := c.cache.Get("pub-" + id); found {
			out = append(out, fingerprint.(string))
			continue
		}

		if isSHA256(id) {
			var val string
			val, err := c.storage.GetKey("raw-" + id)
			if err != nil {
				c.logger.Warn("Can't retrieve public key from Redis:", id, err)
				out = append(out, "")
				continue
			}
			rawKey = []byte(val)
		} else {
			rawKey, err = ioutil.ReadFile(id)
			if err != nil {
				c.logger.Error("Error while reading public key from file:", id, err)
				out = append(out, "")
				continue
			}
		}

		block, _ := pem.Decode(rawKey)
		if block == nil {
			c.logger.Error("Can't parse public key:", id)
			out = append(out, "")
			continue
		}

		fingerprint := tykcrypto.HexSHA256(block.Bytes)
		c.cache.Set("pub-"+id, fingerprint, cache.DefaultExpiration)
		out = append(out, fingerprint)
	}

	return out
}

// Returns list of fingerprints
func (c *certificateManager) ListRawPublicKey(keyID string) (out interface{}) {
	var rawKey []byte
	var err error

	if isSHA256(keyID) {
		var val string
		val, err := c.storage.GetKey("raw-" + keyID)
		if err != nil {
			c.logger.Warn("Can't retrieve public key from Redis:", keyID, err)
			return nil
		}
		rawKey = []byte(val)
	} else {
		rawKey, err = ioutil.ReadFile(keyID)
		if err != nil {
			c.logger.Error("Error while reading public key from file:", keyID, err)
			return nil
		}
	}

	block, _ := pem.Decode(rawKey)
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

// maskCertID masks certificate ID for logging to avoid exposing sensitive data.
// Certificate IDs can be derived from API keys/auth tokens and should not be logged in clear text.
// Returns first 8 characters plus length for debugging while protecting sensitive data.
func maskCertID(certID string) string {
	if len(certID) <= 8 {
		return certID
	}
	return certID[:8] + "***[len=" + strconv.Itoa(len(certID)) + "]"
}

func (c *certificateManager) GetRaw(certID string) (string, error) {
	// Check registry before accessing storage when selective sync is enabled
	if c.selectiveSync && c.registry != nil && !c.registry.Required(certID) {
		c.logger.WithField("cert_id", maskCertID(certID)).
			Info("BLOCKED: certificate not required by loaded APIs")
		return "", errors.New("certificate not required by loaded APIs")
	}
	return c.storage.GetKey("raw-" + certID)
}

// SetRegistry configures the certificate registry for selective sync
func (c *certificateManager) SetRegistry(registry CertUsageTracker) {
	c.logger.Info("Setting certificate registry for selective sync")
	c.registry = registry
	c.selectiveSync = true
	c.logger.WithField("selective_sync", c.selectiveSync).Info("Selective sync configured in CertificateManager")
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
