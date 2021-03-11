package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type dummyStorage struct {
	data      map[string]string
	indexList map[string][]string
}

func newDummyStorage() *dummyStorage {
	return &dummyStorage{
		data:      make(map[string]string),
		indexList: make(map[string][]string),
	}
}

func (s *dummyStorage) GetKey(key string) (string, error) {
	if value, ok := s.data[key]; ok {
		return value, nil
	}

	return "", errors.New("Not found")
}

func (s *dummyStorage) SetKey(key, value string, exp int64) error {
	s.data[key] = value
	return nil
}

func (s *dummyStorage) DeleteKey(key string) bool {
	if _, ok := s.data[key]; !ok {
		return false
	}

	delete(s.data, key)
	return true
}

func (s *dummyStorage) DeleteScanMatch(pattern string) bool {
	if pattern == "*" {
		s.data = make(map[string]string)
		return true
	}

	return false
}

func (s *dummyStorage) RemoveFromList(keyName, value string) error {
	for key, keyList := range s.indexList {
		if key == keyName {
			new := keyList[:]
			newL := 0
			for _, e := range new {
				if e == value {
					continue
				}

				new[newL] = e
				newL++
			}
			new = new[:newL]
			s.indexList[key] = new
		}
	}

	return nil
}

func (s *dummyStorage) GetListRange(keyName string, from, to int64) ([]string, error) {
	for key := range s.indexList {
		if key == keyName {
			return s.indexList[key], nil
		}
	}
	return []string{}, nil
}

func (s *dummyStorage) Exists(keyName string) (bool, error) {
	_, exist := s.indexList[keyName]
	return exist, nil
}

func (s *dummyStorage) AppendToSet(keyName string, value string) {
	s.indexList[keyName] = append(s.indexList[keyName], value)
}

func (s *dummyStorage) GetKeys(pattern string) (keys []string) {
	if pattern != "*" {
		return nil
	}

	for k := range s.data {
		keys = append(keys, k)
	}

	return keys
}

func newManager() *CertificateManager {
	return NewCertificateManager(newDummyStorage(), "test", nil, false)
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
	priv, _ := rsa.GenerateKey(rand.Reader, 512)
	privDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDer})
	pubID := HexSHA256(privDer)

	certRaw, _ := pem.Decode(certPem)
	certID := HexSHA256(certRaw.Bytes)

	cert2Raw, _ := pem.Decode(cert2Pem)
	cert2ID := HexSHA256(cert2Raw.Bytes)

	tests := [...]struct {
		data   []byte
		certID string
		err    string
	}{
		{[]byte(""), "", "Failed to decode certificate. It should be PEM encoded."},
		{[]byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----"), "", "Failed to decode certificate. It should be PEM encoded."},
		{[]byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), "", "asn1: syntax error"},
		{certPem, certID, ""},
		{combinedPemWrongPrivate, "", "tls: private key does not match public key"},
		{combinedPem, cert2ID, ""},
		{combinedPem, "", "Certificate with " + cert2ID + " id already exists"},
		{pubPem, pubID, ""},
		{expiredCertPem, "", "certificate is expired"},
	}

	for _, tc := range tests {
		cid, err := m.Add(tc.data, "")
		if tc.err != "" {
			if err == nil {
				t.Error("Should error with", tc.err)
			} else {
				if !strings.HasPrefix(err.Error(), tc.err) {
					t.Error("Error not match", tc.err, "got:", err)
				}
			}
		} else {
			if err != nil {
				t.Error("Should not error", err)
			}
		}

		if cid != tc.certID {
			t.Error("Wrong certficate ID:", cid, tc.certID)
		}
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
	storage := m.storage.(*dummyStorage)

	if len(storage.indexList) != 0 {
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
	storage.data["raw-raw-orgid-1dummy"] = "test"

	certID, _ := m.Add(storageCert, "orgid-1")

	if len(storage.indexList["orgid-1-index"]) != 1 {
		t.Error("Storage index list should have 1 certificates after adding a certificate")
	}

	m.Delete(certID, "orgid-1")
	if len(storage.indexList["orgid-1-index"]) != 0 {
		t.Error("Storage index list should have 0 certificates after deleting a certificate")
	}
}
