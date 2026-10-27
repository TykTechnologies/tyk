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
	"github.com/stretchr/testify/require"

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

type prefixScanStorage struct {
	*storage.DummyStorage
}

func (s prefixScanStorage) GetKeys(pattern string) []string {
	prefix := strings.TrimSuffix(pattern, "*")
	keys := make([]string, 0)
	for k := range s.Data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

func TestListAllIds_MigrationMarker(t *testing.T) {
	newMigratingManager := func() (*certificateManager, prefixScanStorage) {
		store := prefixScanStorage{storage.NewDummyStorage()}
		return NewCertificateManager(store, "test", nil, true), store
	}

	t.Run("listing without prefix returns all certificates on every call", func(t *testing.T) {
		m, store := newMigratingManager()

		certNoOrg, _ := genCertificateFromCommonName("no-org", false)
		certOrg, _ := genCertificateFromCommonName("with-org", false)
		idNoOrg, err := m.Add(certNoOrg, "")
		assert.NoError(t, err)
		idOrg, err := m.Add(certOrg, "orgid-1")
		assert.NoError(t, err)

		for i := 0; i < 3; i++ {
			assert.ElementsMatch(t, []string{idNoOrg, idOrg}, m.ListAllIds(""), "call %d", i+1)
		}

		_, err = store.GetKey("-index-migrated")
		assert.Error(t, err, "no migrated marker should be written for an empty prefix")
	})

	t.Run("stale marker for empty prefix is ignored", func(t *testing.T) {
		m, store := newMigratingManager()

		// Simulates a Redis populated by a gateway running the old code.
		assert.NoError(t, store.SetKey("-index-migrated", "1", 0))

		cert, _ := genCertificateFromCommonName("no-org", false)
		id, err := m.Add(cert, "")
		assert.NoError(t, err)

		assert.Equal(t, []string{id}, m.ListAllIds(""))
	})

	t.Run("org with no certificates is not rescanned after migration", func(t *testing.T) {
		m, store := newMigratingManager()

		assert.Empty(t, m.ListAllIds("orgid-1"))
		_, err := store.GetKey("orgid-1-index-migrated")
		assert.NoError(t, err, "migrated marker should be set for an org-scoped listing")

		// A record outside the index must stay invisible once migration is done.
		store.Data["raw-orgid-1dummy"] = "test"
		assert.Empty(t, m.ListAllIds("orgid-1"))
	})

	t.Run("duplicate index entries are returned once", func(t *testing.T) {
		m, store := newMigratingManager()

		certA, _ := genCertificateFromCommonName("a", false)
		certB, _ := genCertificateFromCommonName("b", false)
		idA, err := m.Add(certA, "orgid-1")
		assert.NoError(t, err)
		idB, err := m.Add(certB, "orgid-1")
		assert.NoError(t, err)

		// Duplicates written by older versions (e.g. data planes appending to
		// the control plane's index).
		store.AppendToSet("orgid-1-index", "raw-"+idA)
		store.AppendToSet("orgid-1-index", "raw-"+idB)
		store.AppendToSet("orgid-1-index", "raw-"+idA)

		assert.Equal(t, []string{idA, idB}, m.ListAllIds("orgid-1"))

		// Deleting removes every copy from the index.
		m.Delete(idA, "orgid-1")
		assert.Equal(t, []string{idB}, m.ListAllIds("orgid-1"))
	})

	t.Run("org listing migrates legacy certificates into the index", func(t *testing.T) {
		m, store := newMigratingManager()

		store.Data["raw-orgid-1legacy"] = "legacy"
		store.Data["raw-orgid-2other"] = "other"

		assert.Equal(t, []string{"orgid-1legacy"}, m.ListAllIds("orgid-1"))
		assert.Equal(t, []string{"raw-orgid-1legacy"}, store.IndexList["orgid-1-index"])
		assert.Equal(t, []string{"orgid-1legacy"}, m.ListAllIds("orgid-1"))
	})
}

func TestListPublicKeys_EmbeddedPEM(t *testing.T) {
	m := newManager()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	privDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	assert.NoError(t, err)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDer})
	expectedFingerprint := tykcrypto.HexSHA256(privDer)

	t.Run("ListPublicKeys decodes inline PEM", func(t *testing.T) {
		out := m.ListPublicKeys([]string{string(pubPem)})

		assert.Len(t, out, 1)
		assert.Equal(t, expectedFingerprint, out[0])
	})

	t.Run("ListPublicKeys leading/trailing whitespace tolerated", func(t *testing.T) {
		out := m.ListPublicKeys([]string{"\n  " + string(pubPem) + "  \n"})

		assert.Len(t, out, 1)
		assert.Equal(t, expectedFingerprint, out[0])
	})

	t.Run("ListPublicKeys tolerates single-line collapsed PEM", func(t *testing.T) {
		// A paste into a single-line field flattens line breaks into spaces,
		// exactly as the embedded-cert path in List() already tolerates.
		collapsed := strings.ReplaceAll(strings.TrimSpace(string(pubPem)), "\n", " ")
		out := m.ListPublicKeys([]string{collapsed})

		assert.Len(t, out, 1)
		assert.Equal(t, expectedFingerprint, out[0])
	})

	t.Run("ListRawPublicKey parses inline PEM", func(t *testing.T) {
		out := m.ListRawPublicKey(string(pubPem))

		assert.NotNil(t, out)
	})

	t.Run("malformed inline PEM fails gracefully", func(t *testing.T) {
		out := m.ListPublicKeys([]string{"-----BEGIN PUBLIC KEY-----\nbogus\n-----END PUBLIC KEY-----"})

		assert.Len(t, out, 1)
		assert.Equal(t, "", out[0])
	})
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
func collapseToSingleLine(v []byte) string {
	return strings.ReplaceAll(strings.TrimSpace(string(v)), "\n", " ")
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

// rpcStorageStub mimics gateway.RPCStorageHandler as seen by a data plane:
// GetKey, SetKey and AppendToSet reach the control plane (backed here by a
// DummyStorage), while Exists, GetKeys, GetListRange and RemoveFromList are
// not implemented and return empty results.
type rpcStorageStub struct {
	*storage.DummyStorage
}

func (rpcStorageStub) Exists(string) (bool, error)                         { return false, nil }
func (rpcStorageStub) GetKeys(string) []string                             { return nil }
func (rpcStorageStub) GetListRange(string, int64, int64) ([]string, error) { return nil, nil }
func (rpcStorageStub) RemoveFromList(string, string) error                 { return nil }

type mdcbFixture struct {
	controlPlane *storage.DummyStorage
	local        prefixScanStorage
	dataPlane    *certificateManager
	orgCertID    string
	noOrgCertID  string
}

// newMdcbFixture stores two certificates on the control plane (one for org
// "orgid-1", one without an org) and lets the data plane pull both into its
// local Redis, which is what happens when an API that uses them is loaded.
func newMdcbFixture(t *testing.T) *mdcbFixture {
	t.Helper()

	cp := storage.NewDummyStorage()
	controlPlane := NewCertificateManager(prefixScanStorage{cp}, "test", nil, true)

	orgCert, _ := genCertificateFromCommonName("org-cert", false)
	noOrgCert, _ := genCertificateFromCommonName("no-org-cert", false)
	orgCertID, err := controlPlane.Add(orgCert, "orgid-1")
	require.NoError(t, err)
	noOrgCertID, err := controlPlane.Add(noOrgCert, "")
	require.NoError(t, err)

	local := prefixScanStorage{storage.NewDummyStorage()}
	dataPlane := NewSlaveCertManager(local, rpcStorageStub{cp}, "test", nil, true)

	for _, id := range []string{orgCertID, noOrgCertID} {
		_, err := dataPlane.GetRaw(id)
		require.NoError(t, err)
		_, err = local.GetKey("raw-" + id)
		require.NoError(t, err, "certificate should be cached in the data plane's local storage")
	}

	return &mdcbFixture{
		controlPlane: cp,
		local:        local,
		dataPlane:    dataPlane,
		orgCertID:    orgCertID,
		noOrgCertID:  noOrgCertID,
	}
}

func TestListAllIds_MDCBDataPlane(t *testing.T) {
	t.Run("org listing returns cached certificates on every call", func(t *testing.T) {
		f := newMdcbFixture(t)
		for i := 0; i < 3; i++ {
			assert.Equal(t, []string{f.orgCertID}, f.dataPlane.ListAllIds("orgid-1"), "call %d", i+1)
		}
	})

	t.Run("listing without org returns cached certificates on every call", func(t *testing.T) {
		f := newMdcbFixture(t)
		for i := 0; i < 3; i++ {
			assert.ElementsMatch(t, []string{f.orgCertID, f.noOrgCertID}, f.dataPlane.ListAllIds(""), "call %d", i+1)
		}
	})

	t.Run("control plane migration markers do not hide local certificates", func(t *testing.T) {
		f := newMdcbFixture(t)
		// Set by any control plane gateway that has listed certificates.
		require.NoError(t, f.controlPlane.SetKey("orgid-1-index-migrated", "1", 0))
		require.NoError(t, f.controlPlane.SetKey("-index-migrated", "1", 0))

		assert.Equal(t, []string{f.orgCertID}, f.dataPlane.ListAllIds("orgid-1"))
		assert.ElementsMatch(t, []string{f.orgCertID, f.noOrgCertID}, f.dataPlane.ListAllIds(""))
	})

	t.Run("listing does not write to the control plane", func(t *testing.T) {
		f := newMdcbFixture(t)
		before := append([]string(nil), f.controlPlane.IndexList["orgid-1-index"]...)
		dataBefore := len(f.controlPlane.Data)

		for i := 0; i < 3; i++ {
			f.dataPlane.ListAllIds("orgid-1")
			f.dataPlane.ListAllIds("")
		}

		assert.Equal(t, before, f.controlPlane.IndexList["orgid-1-index"])
		assert.Equal(t, dataBefore, len(f.controlPlane.Data))
	})

	t.Run("duplicates left in the local index by older versions are returned once", func(t *testing.T) {
		f := newMdcbFixture(t)
		// Old code: Add appended on pull, then the first listing's migration
		// scan appended the same key again before setting the marker.
		f.local.AppendToSet("orgid-1-index", "raw-"+f.orgCertID)
		require.NoError(t, f.local.SetKey("orgid-1-index-migrated", "1", 0))
		require.Len(t, f.local.IndexList["orgid-1-index"], 2)

		assert.Equal(t, []string{f.orgCertID}, f.dataPlane.ListAllIds("orgid-1"))
	})

	t.Run("org with no cached certificates stays empty without rescanning", func(t *testing.T) {
		f := newMdcbFixture(t)
		assert.Empty(t, f.dataPlane.ListAllIds("orgid-2"))
		_, err := f.local.GetKey("orgid-2-index-migrated")
		assert.NoError(t, err, "marker should be written to the data plane's local storage")
		assert.Empty(t, f.dataPlane.ListAllIds("orgid-2"))
	})
}
