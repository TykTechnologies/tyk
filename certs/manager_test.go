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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type dummyStorage struct {
	data      map[string]string
	indexList map[string][]string
}

func (s *dummyStorage) GetMultiKey([]string) ([]string, error) {
	panic("implement me")
}

func (s *dummyStorage) GetRawKey(string) (string, error) {
	panic("implement me")
}

func (s *dummyStorage) SetRawKey(string, string, int64) error {
	panic("implement me")
}

func (s *dummyStorage) SetExp(string, int64) error {
	panic("implement me")
}

func (s *dummyStorage) GetExp(string) (int64, error) {
	panic("implement me")
}

func (s *dummyStorage) DeleteAllKeys() bool {
	panic("implement me")
}

func (s *dummyStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

func (s *dummyStorage) Connect() bool {
	panic("implement me")
}

func (s *dummyStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (s *dummyStorage) GetKeysAndValuesWithFilter(string) map[string]string {
	panic("implement me")
}

func (s *dummyStorage) DeleteKeys([]string) bool {
	panic("implement me")
}

func (s *dummyStorage) Decrement(string) {
	panic("implement me")
}

func (s *dummyStorage) IncrememntWithExpire(string, int64) int64 {
	panic("implement me")
}

func (s *dummyStorage) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *dummyStorage) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *dummyStorage) GetSet(string) (map[string]string, error) {
	panic("implement me")
}

func (s *dummyStorage) AddToSet(string, string) {
	panic("implement me")
}

func (s *dummyStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

func (s *dummyStorage) RemoveFromSet(string, string) {
	panic("implement me")
}

func (s *dummyStorage) GetKeyPrefix() string {
	panic("implement me")
}

func (s *dummyStorage) AddToSortedSet(string, string, float64) {
	panic("implement me")
}

func (s *dummyStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	panic("implement me")
}

func (s *dummyStorage) RemoveSortedSetRange(string, string, string) error {
	panic("implement me")
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
	_, existIndex := s.indexList[keyName]
	_, existRaw := s.data[keyName]
	return existIndex || existRaw, nil
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
