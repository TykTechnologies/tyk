package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/storage"

	cache "github.com/pmylund/go-cache"
	"github.com/sirupsen/logrus"
)

var CertManagerLogPrefix = "cert_storage"

type CertificateManager struct {
	storage         storage.Handler
	logger          *logrus.Entry
	cache           *cache.Cache
	secret          string
	migrateCertList bool
}

func NewCertificateManager(storage storage.Handler, secret string, logger *logrus.Logger, migrateCertList bool) *CertificateManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &CertificateManager{
		storage:         storage,
		logger:          logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix}),
		cache:           cache.New(5*time.Minute, 10*time.Minute),
		secret:          secret,
		migrateCertList: migrateCertList,
	}
}

func getOrgFromKeyID(key, certID string) string {
	orgId := strings.ReplaceAll(key, "raw-", "")
	orgId = strings.ReplaceAll(orgId, certID, "")
	return orgId
}

func NewSlaveCertManager(localStorage, rpcStorage storage.Handler, secret string, logger *logrus.Logger, migrateCertList bool) *CertificateManager {
	if logger == nil {
		logger = logrus.New()
	}
	log := logger.WithFields(logrus.Fields{"prefix": CertManagerLogPrefix})

	cm := &CertificateManager{
		logger:          log,
		cache:           cache.New(5*time.Minute, 10*time.Minute),
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

	mdcbStorage := storage.NewMdcbStorage(localStorage, rpcStorage, log)
	mdcbStorage.CallbackonPullfromRPC = &callbackOnPullCertFromRPC

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

func HexSHA256(cert []byte) string {
	certSHA := sha256.Sum256(cert)
	return hex.EncodeToString(certSHA[:])
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
			certID = HexSHA256(block.Bytes)
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
			cert.Leaf = &x509.Certificate{Subject: pkix.Name{CommonName: "Public Key: " + HexSHA256(block.Bytes)}}
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

		certID = HexSHA256(cert.Certificate[0])
	} else if len(publicKeyPem) > 0 {
		publicKey, _ := pem.Decode(publicKeyPem)
		certID = HexSHA256(publicKey.Bytes)
	} else {
		// Get first cert
		certRaw, _ := pem.Decode(certChainPEM)
		cert, err := x509.ParseCertificate(certRaw.Bytes)
		if err != nil {
			err := errors.New("Error while parsing certificate: " + err.Error())
			return certID, certChainPEM, err
		}

		certID = HexSHA256(cert.Raw)
	}
	return certID, certChainPEM, nil
}

func (c *CertificateManager) List(certIDs []string, mode CertificateType) (out []*tls.Certificate) {
	var cert *tls.Certificate
	var rawCert []byte

	for _, id := range certIDs {
		if cert, found := c.cache.Get(id); found {
			if isCertCanBeListed(cert.(*tls.Certificate), mode) {
				out = append(out, cert.(*tls.Certificate))
			}
			continue
		}

		val, err := c.storage.GetKey("raw-" + id)
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
func (c *CertificateManager) ListPublicKeys(keyIDs []string) (out []string) {
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

		fingerprint := HexSHA256(block.Bytes)
		c.cache.Set("pub-"+id, fingerprint, cache.DefaultExpiration)
		out = append(out, fingerprint)
	}

	return out
}

// Returns list of fingerprints
func (c *CertificateManager) ListRawPublicKey(keyID string) (out interface{}) {
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

func (c *CertificateManager) ListAllIds(prefix string) (out []string) {
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

func (c *CertificateManager) GetRaw(certID string) (string, error) {
	return c.storage.GetKey("raw-" + certID)
}

func (c *CertificateManager) Add(certData []byte, orgID string) (string, error) {

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

func (c *CertificateManager) Delete(certID string, orgID string) {

	if orgID != "" {
		c.storage.RemoveFromList(orgID+"-index", "raw-"+certID)
	}

	c.storage.DeleteKey("raw-" + certID)
	c.cache.Delete(certID)
}

func (c *CertificateManager) CertPool(certIDs []string) *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range c.List(certIDs, CertificatePublic) {
		if cert != nil {
			pool.AddCert(cert.Leaf)
		}
	}

	return pool
}

func (c *CertificateManager) ValidateRequestCertificate(certIDs []string, r *http.Request) error {
	if r.TLS == nil {
		return errors.New("TLS not enabled")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return errors.New("Client TLS certificate is required")
	}

	leaf := r.TLS.PeerCertificates[0]

	certID := HexSHA256(leaf.Raw)
	for _, cert := range c.List(certIDs, CertificatePublic) {
		// In case a cert can't be parsed or is invalid,
		// it will be present in the cert list as 'nil'
		if cert == nil {
			// Invalid cert, continue to next one
			continue
		}

		// Extensions[0] contains cache of certificate SHA256
		if string(cert.Leaf.Extensions[0].Value) == certID {
			// Happy flow, we matched a certificate
			return nil
		}
	}

	return errors.New("Certificate with SHA256 " + certID + " not allowed")
}

func (c *CertificateManager) FlushCache() {
	c.cache.Flush()
}

func (c *CertificateManager) flushStorage() {
	c.storage.DeleteScanMatch("*")
}
