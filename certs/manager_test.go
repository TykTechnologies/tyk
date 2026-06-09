package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

func newManager() *certificateManager {
	return NewCertificateManager(storage.NewDummyStorage(), "test", nil, false, WithMaxRetries(3))
}

func genCertificate(template *x509.Certificate, isExpired bool) ([]byte, []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()

	var notAfter time.Duration = time.Hour
	if isExpired {
		notAfter = -1 * time.Hour
	}

	template.NotAfter = time.Now().Add(notAfter)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem, keyPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPem.Bytes(), keyPem.Bytes()
}

func genCertificateFromCommonName(cn string, isExpired bool) ([]byte, []byte) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return genCertificate(tmpl, isExpired)
}

func leafSubjectName(cert *tls.Certificate) string {
	return cert.Leaf.Subject.CommonName
}

func TestAddCertificate(t *testing.T) {
	m := newManager()

	expiredCertPem, _ := genCertificateFromCommonName("expired", true)
	certPem, keyPem := genCertificateFromCommonName("test", false)
	cert2Pem, key2Pem := genCertificateFromCommonName("test2", false)
	combinedPem := append(cert2Pem, key2Pem...)
	combinedPemWrongPrivate := append(cert2Pem, keyPem...)

	// crypto/rsa: 512-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDer})
	pubID := tykcrypto.HexSHA256(privDer)

	certRaw, _ := pem.Decode(certPem)
	certID := tykcrypto.HexSHA256(certRaw.Bytes)

	cert2Raw, _ := pem.Decode(cert2Pem)
	cert2ID := tykcrypto.HexSHA256(cert2Raw.Bytes)

	emptyCertID := ""

	withError := true
	noError := false

	testcases := []struct {
		title  string
		data   []byte
		certID string
		err    bool
	}{
		{"empty cert", []byte(""), emptyCertID, withError},
		{"invalid cert: pem", []byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----"), emptyCertID, withError},
		{"invalid cert: asn1", []byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), emptyCertID, withError},
		{"valid cert 1", certPem, certID, noError},
		{"tls: wrong private", combinedPemWrongPrivate, emptyCertID, withError},
		{"valid cert 2", combinedPem, cert2ID, noError},
		{"combined pem exists", combinedPem, emptyCertID, withError},
		{"valid public pem", pubPem, pubID, noError},
		{"expired cert", expiredCertPem, emptyCertID, withError},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			cid, err := m.Add(tc.data, "")

			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.certID, cid)
		})
	}
}

func TestCertificateStorage(t *testing.T) {
	m := newManager()
	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
	}()

	certPem, _ := genCertificateFromCommonName("file", false)
	certPath := filepath.Join(dir, "cert.pem")
	ioutil.WriteFile(certPath, certPem, 0666)

	privateCertPEM, keyCertPEM := genCertificateFromCommonName("private", false)
	privateCertID, _ := m.Add(append(privateCertPEM, keyCertPEM...), "")

	storageCert, _ := genCertificateFromCommonName("dummy", false)
	storageCertID, _ := m.Add(storageCert, "")

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDer})
	publicKeyID, _ := m.Add(pubPem, "")

	t.Run("File certificates", func(t *testing.T) {
		certs := m.List([]string{certPath, "wrong"}, CertificatePublic)
		if len(certs) != 2 {
			t.Fatal("Should contain 2 cert", len(certs))
		}

		if certs[1] != nil {
			t.Fatal("Wrong certificate should be returned as nil")
		}

		if leafSubjectName(certs[0]) != "file" {
			t.Fatal("Should return valid cert")
		}
	})

	t.Run("Remote storage certificates", func(t *testing.T) {
		certs := m.List([]string{certPath, storageCertID, privateCertID}, CertificatePublic)

		if len(certs) != 3 {
			t.Fatal("Should contain 3 certs but", len(certs))
		}

		assert.Equal(t, "file", leafSubjectName(certs[0]))
		assert.Equal(t, "dummy", leafSubjectName(certs[1]))
		assert.Equal(t, "private", leafSubjectName(certs[2]))
	})

	t.Run("Private certificates", func(t *testing.T) {
		certs := m.List([]string{certPath, storageCertID, privateCertID}, CertificatePrivate)

		if len(certs) != 1 {
			t.Error("Should return only private certificate")
		}

		if leafSubjectName(certs[0]) != "private" || isPrivateKeyEmpty(certs[0]) {
			t.Error("Wrong cert", leafSubjectName(certs[0]))
		}
	})

	t.Run("Public keys", func(t *testing.T) {
		certs := m.List([]string{publicKeyID}, CertificatePublic)

		if len(certs) != 1 {
			t.Error("Should return only private certificate")
		}

		if leafSubjectName(certs[0]) != ("Public Key: " + publicKeyID) {
			t.Error("Wrong cert", leafSubjectName(certs[0]))
		}
	})
}

func TestStorageIndex(t *testing.T) {
	m := newManager()
	storageCert, _ := genCertificateFromCommonName("dummy", false)
	storage, ok := m.storage.(*storage.DummyStorage)

	if !ok {
		t.Error("cannot make storage.DummyStorage of type storage.Handler")
	}

	if len(storage.IndexList) != 0 {
		t.Error("Storage index list should have 0 certificates and indexes after creation")
	}
	if _, err := storage.GetKey("orgid-1-index-migrated"); err == nil {
		t.Error("There should not be migration done")
	}

	m.ListAllIds("orgid-1")
	if _, err := storage.GetKey("orgid-1-index-migrated"); err != nil {
		t.Error("Migrated flag should be set after first listing", err)
	}
	// Set recound outside of collection. It should not be visible if migration was applied.
	storage.Data["raw-raw-orgid-1dummy"] = "test"

	certID, _ := m.Add(storageCert, "orgid-1")

	if len(storage.IndexList["orgid-1-index"]) != 1 {
		t.Error("Storage index list should have 1 certificates after adding a certificate")
	}

	m.Delete(certID, "orgid-1")
	if len(storage.IndexList["orgid-1-index"]) != 0 {
		t.Error("Storage index list should have 0 certificates after deleting a certificate")
	}
}

func TestToCertificateBasics(t *testing.T) {
	now := time.Now()

	meta := &CertificateMeta{
		ID:            "cert-123",
		Fingerprint:   "fingerprint-123",
		HasPrivateKey: true,
		Issuer: pkix.Name{
			CommonName: "Issuer CN",
		},
		Subject: pkix.Name{
			CommonName: "Subject CN",
		},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		DNSNames:  []string{"tyk.com", "www.tyk.com"},
		IsCA:      true,
	}

	basics := meta.ToCertificateBasics()

	assert.NotNil(t, basics)
	assert.Equal(t, meta.ID, basics.ID)
	assert.Equal(t, meta.Issuer.CommonName, basics.IssuerCN)
	assert.Equal(t, meta.Subject.CommonName, basics.SubjectCN)
	assert.Equal(t, meta.DNSNames, basics.DNSNames)
	assert.Equal(t, meta.HasPrivateKey, basics.HasPrivateKey)
	assert.Equal(t, meta.NotBefore, basics.NotBefore)
	assert.Equal(t, meta.NotAfter, basics.NotAfter)
	assert.Equal(t, meta.IsCA, basics.IsCA)
}

// The following test functions all verify CertificateManager.List accepts
// inline PEM strings in addition to certificate IDs and file paths. They are
// split into independent top-level functions (rather than a single test with
// many t.Run subtests) to keep individual cognitive complexity low.

// requireSingleCert is a tiny helper that asserts the single-cert case shape.
func requireSingleCert(t *testing.T, certs []*tls.Certificate) *tls.Certificate {
	t.Helper()
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0] == nil {
		t.Fatal("expected cert, got nil")
	}
	return certs[0]
}

func TestList_EmbeddedPEM_SingleCert(t *testing.T) {
	m := newManager()
	certPem, _ := genCertificateFromCommonName("embedded", false)

	certs := m.List([]string{string(certPem)}, CertificatePublic)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "embedded", leafSubjectName(cert))
}

func TestList_EmbeddedPEM_CombinedCertKey_ResolvesAsPrivate(t *testing.T) {
	m := newManager()
	certPem, keyPem := genCertificateFromCommonName("embedded", false)
	combinedPem := append(append([]byte{}, certPem...), keyPem...)

	certs := m.List([]string{string(combinedPem)}, CertificatePrivate)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "embedded", leafSubjectName(cert))
	assert.False(t, isPrivateKeyEmpty(cert), "private key should be present")
}

func TestList_EmbeddedPEM_MixedBatch(t *testing.T) {
	m := newManager()

	filePem, _ := genCertificateFromCommonName("file", false)
	dir, err := ioutil.TempDir("", "certs-embedded-mix")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	filePath := filepath.Join(dir, "cert.pem")
	if err := ioutil.WriteFile(filePath, filePem, 0666); err != nil {
		t.Fatal(err)
	}

	storagePem, _ := genCertificateFromCommonName("storage", false)
	storageID, err := m.Add(storagePem, "")
	if err != nil {
		t.Fatal(err)
	}

	embeddedPem, _ := genCertificateFromCommonName("embedded-mix", false)

	certs := m.List([]string{filePath, storageID, string(embeddedPem)}, CertificatePublic)
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}
	assert.Equal(t, "file", leafSubjectName(certs[0]))
	assert.Equal(t, "storage", leafSubjectName(certs[1]))
	assert.Equal(t, "embedded-mix", leafSubjectName(certs[2]))
}

func TestList_EmbeddedPEM_LeadingTrailingWhitespace(t *testing.T) {
	m := newManager()
	certPem, _ := genCertificateFromCommonName("embedded", false)

	padded := "\n\n  " + string(certPem) + "\n\n  "
	certs := m.List([]string{padded}, CertificatePublic)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "embedded", leafSubjectName(cert))
}

func TestList_EmbeddedPEM_CRLFLineEndings(t *testing.T) {
	m := newManager()
	certPem, _ := genCertificateFromCommonName("embedded", false)

	crlf := strings.ReplaceAll(string(certPem), "\n", "\r\n")
	certs := m.List([]string{crlf}, CertificatePublic)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "embedded", leafSubjectName(cert))
}

func TestList_EmbeddedPEM_MalformedBodyReturnsNil(t *testing.T) {
	m := newManager()
	bad := "-----BEGIN CERTIFICATE-----\nnot-base64-data\n-----END CERTIFICATE-----"

	certs := m.List([]string{bad}, CertificatePublic)

	if len(certs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(certs))
	}
	assert.Nil(t, certs[0], "malformed PEM must yield nil entry")
}

func TestList_EmbeddedPEM_TruncatedReturnsNil(t *testing.T) {
	m := newManager()
	bad := "-----BEGIN CERTIFICATE-----\nMIIB"

	certs := m.List([]string{bad}, CertificatePublic)

	if len(certs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(certs))
	}
	assert.Nil(t, certs[0], "truncated PEM must yield nil entry")
}

func TestList_EmbeddedPEM_CacheKeyUsesContentHash(t *testing.T) {
	m := newManager()
	pem2, _ := genCertificateFromCommonName("cache-test", false)
	before := m.cache.Count()

	// First call: populates cache.
	requireSingleCert(t, m.List([]string{string(pem2)}, CertificatePublic))
	after1 := m.cache.Count()
	assert.Equal(t, before+1, after1, "first call should add one cache entry")

	// Second call: must hit cache (no new entry).
	requireSingleCert(t, m.List([]string{string(pem2)}, CertificatePublic))
	after2 := m.cache.Count()
	assert.Equal(t, after1, after2, "second call with same PEM should hit cache (no new entry)")

	// Cache key derived from SHA256 of trimmed content, not the raw string.
	expectedKey := embeddedPEMCacheKeyPrefix + tykcrypto.HexSHA256([]byte(strings.TrimSpace(string(pem2))))
	cached, found := m.cache.Get(expectedKey)
	assert.True(t, found, "cache should hold entry under embedded-pem-<sha256> key")
	assert.NotNil(t, cached)

	_, foundRaw := m.cache.Get(string(pem2))
	assert.False(t, foundRaw, "raw PEM string must not be used as cache key")
}

func TestList_EmbeddedPEM_MultiCertChain(t *testing.T) {
	m := newManager()
	leafPem, _ := genCertificateFromCommonName("leaf", false)
	intermediatePem, _ := genCertificateFromCommonName("intermediate", false)
	chain := append(append([]byte{}, leafPem...), intermediatePem...)

	certs := m.List([]string{string(chain)}, CertificatePublic)

	cert := requireSingleCert(t, certs)
	assert.Len(t, cert.Certificate, 2, "chain should contain leaf + intermediate")
}

func TestList_EmbeddedPEM_CertPoolWithEmbeddedCA(t *testing.T) {
	m := newManager()
	caPem, _ := genCertificateFromCommonName("ca-embedded", false)

	pool := m.CertPool([]string{string(caPem)})

	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	// pool.Subjects() is deprecated but acceptable here for a population check.
	subjects := pool.Subjects()
	assert.GreaterOrEqual(t, len(subjects), 1, "pool should contain at least the embedded CA")
}

// collapseToSingleLine simulates a copy-paste of a PEM into a single-line text
// field: every newline becomes a space.
func collapseToSingleLine(pem []byte) string {
	return strings.ReplaceAll(strings.TrimSpace(string(pem)), "\n", " ")
}

// TestList_EmbeddedPEM_SingleLineCollapsed verifies the gateway tolerates a
// PEM whose line breaks were collapsed into spaces (e.g. pasted into a
// single-line Dashboard field). pem.Decode rejects this form, so List() must
// repair it before parsing.
func TestList_EmbeddedPEM_SingleLineCollapsed(t *testing.T) {
	m := newManager()
	certPem, _ := genCertificateFromCommonName("single-line", false)

	certs := m.List([]string{collapseToSingleLine(certPem)}, CertificatePublic)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "single-line", leafSubjectName(cert))
}

// TestList_EmbeddedPEM_SingleLineCombinedCertKey verifies a combined cert+key
// PEM (used by upstream_certificates) is also tolerated when collapsed.
func TestList_EmbeddedPEM_SingleLineCombinedCertKey(t *testing.T) {
	m := newManager()
	certPem, keyPem := genCertificateFromCommonName("single-line-priv", false)
	combined := append(append([]byte{}, certPem...), keyPem...)

	certs := m.List([]string{collapseToSingleLine(combined)}, CertificatePrivate)

	cert := requireSingleCert(t, certs)
	assert.Equal(t, "single-line-priv", leafSubjectName(cert))
	assert.False(t, isPrivateKeyEmpty(cert), "private key should survive normalization")
}
