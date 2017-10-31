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
	return NewCertificateManager(newDummyStorage(), "test", nil)
}

func genCertificate(template *x509.Certificate) ([]byte, []byte) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem, keyPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPem.Bytes(), keyPem.Bytes()
}

func genCertificateFromCommonName(cn string) ([]byte, []byte) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return genCertificate(tmpl)
}

func leafSubjectName(cert *tls.Certificate) string {
	x509сert, _ := x509.ParseCertificate(cert.Certificate[0])
	return x509сert.Subject.CommonName
}

func TestAddCertificate(t *testing.T) {
	m := newManager()

	certPem, keyPem := genCertificateFromCommonName("test")
	cert2Pem, key2Pem := genCertificateFromCommonName("test2")
	combinedPem := append(cert2Pem, key2Pem...)
	combinedPemWrongPrivate := append(cert2Pem, keyPem...)

	certRaw, _ := pem.Decode(cert2Pem)
	certID := HexSHA256(certRaw.Bytes)

	tests := [...]struct {
		data []byte
		err  string
	}{
		{[]byte(""), "Failed to decode certificate. It should be PEM encoded."},
		{[]byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----"), "Failed to decode certificate. It should be PEM encoded."},
		{[]byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"), "Error while parsing certificate: asn1: syntax error"},
		{certPem, ""},
		{combinedPemWrongPrivate, "tls: private key does not match public key"},
		{combinedPem, ""},
		{combinedPem, "Certificate with " + certID + " id already exists"},
	}

	for _, tc := range tests {
		_, err := m.Add(tc.data, "")
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
	}
}

func TestCertificateStorage(t *testing.T) {
	m := newManager()
	dir, _ := ioutil.TempDir("", "certs")

	defer func() {
		os.RemoveAll(dir)
	}()

	certPem, _ := genCertificateFromCommonName("file")
	certPath := filepath.Join(dir, "cert.pem")
	ioutil.WriteFile(certPath, certPem, 0666)

	privateCertPEM, keyCertPEM := genCertificateFromCommonName("private")
	privateCertID, _ := m.Add(append(privateCertPEM, keyCertPEM...), "")

	storageCert, _ := genCertificateFromCommonName("dummy")
	storageCertID, _ := m.Add(storageCert, "")

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
}
