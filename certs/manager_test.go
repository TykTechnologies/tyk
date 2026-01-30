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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

func newManager() *certificateManager {
	return NewCertificateManager(storage.NewDummyStorage(), "test", nil, false, 0, 0, 0)
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
