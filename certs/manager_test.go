package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

type dummyStorage struct {
	data map[string]string
}

func newDummyStorage() *dummyStorage {
	return &dummyStorage{
		data: make(map[string]string),
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
	return NewCertificateManager(NewStorageHandlerWrapper(newDummyStorage()), "test", nil)
}

func leafSubjectName(cert *tls.Certificate) string {
	return cert.Leaf.Subject.CommonName
}

func TestAddCertificate(t *testing.T) {
	m := newManager()

	certPem, keyPem, _, _ := test.GenCertificateFromCommonName("test")
	cert2Pem, key2Pem, _, _ := test.GenCertificateFromCommonName("test2")
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
		{[]byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), "", "Error while parsing certificate: asn1: syntax error"},
		{certPem, certID, ""},
		{combinedPemWrongPrivate, "", "tls: private key does not match public key"},
		{combinedPem, cert2ID, ""},
		{combinedPem, "", "Certificate with " + cert2ID + " id already exists"},
		{pubPem, pubID, ""},
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

	certPem, _, _, _ := test.GenCertificateFromCommonName("file")
	certPath := filepath.Join(dir, "cert.pem")
	ioutil.WriteFile(certPath, certPem, 0666)

	privateCertPEM, keyCertPEM, _, _ := test.GenCertificateFromCommonName("private")
	privateCertID, _ := m.Add(append(privateCertPEM, keyCertPEM...), "")

	storageCert, _, _, _ := test.GenCertificateFromCommonName("dummy")
	storageCertID, _ := m.Add(storageCert, "")

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: privDer})
	publicKeyID, _ := m.Add(pubPem, "")

	t.Run("File certificates", func(t *testing.T) {
		certs := m.List([]string{certPath, "wrong"}, CertificatePublic)
		if len(certs) != 2 {
			t.Fatal("Should contain 1 cert", len(certs))
		}

		if certs[1] != nil {
			t.Fatal("Wrong certificate should be returned as nil")
		}

		if leafSubjectName(certs[0]) != "file" {
			t.Fatal("Should return valid cert")
		}
	})

	t.Run("Remote storage certficates", func(t *testing.T) {
		certs := m.List([]string{certPath, storageCertID, privateCertID}, CertificatePublic)

		if len(certs) != 2 {
			t.Fatal("Should contain 2 cert", len(certs))
		}

		if leafSubjectName(certs[0]) != "file" {
			t.Error("Wrong cert order", leafSubjectName(certs[0]))
		}

		if leafSubjectName(certs[1]) != "dummy" {
			t.Error("Wrong cert order", leafSubjectName(certs[1]))
		}
	})

	t.Run("Private certficates", func(t *testing.T) {
		certs := m.List([]string{certPath, storageCertID, privateCertID}, CertificatePrivate)

		if len(certs) != 1 {
			t.Error("Should return only private certificate")
		}

		if leafSubjectName(certs[0]) != "private" || isPrivateKeyEmpty(certs[0]) {
			t.Error("Wrong cert", leafSubjectName(certs[0]))
		}
	})

	t.Run("Public keys", func(t *testing.T) {
		certs := m.List([]string{publicKeyID}, CertificateAny)

		if len(certs) != 1 {
			t.Error("Should return only private certificate")
		}

		if leafSubjectName(certs[0]) != ("Public Key: " + publicKeyID) {
			t.Error("Wrong cert", leafSubjectName(certs[0]))
		}
	})
}
