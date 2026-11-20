package certs

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
)

func TestCertificateFingerprint(t *testing.T) {
	certPEM, keyPEM, combinedPEM, tlsCert := tykcrypto.GenServerCertificate()
	want := tykcrypto.HexSHA256(tlsCert.Certificate[0])

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	t.Run("matches the ID the store gives the certificate", func(t *testing.T) {
		m := newManager()
		id, err := m.Add(combinedPEM, "")
		require.NoError(t, err)

		assert.Equal(t, id, CertificateFingerprint(combinedPEM))
		assert.Equal(t, want, CertificateFingerprint(certPEM))
	})

	t.Run("key before the certificate", func(t *testing.T) {
		assert.Equal(t, want, CertificateFingerprint(append(append([]byte{}, keyPEM...), certPEM...)))
	})

	t.Run("public key", func(t *testing.T) {
		assert.Equal(t, tykcrypto.HexSHA256(pubDER), CertificateFingerprint(pubPEM))
		assert.Equal(t, tykcrypto.HexSHA256(pubDER), PublicKeyFingerprint(pubPEM))
	})

	t.Run("line breaks collapsed into spaces", func(t *testing.T) {
		collapsed := strings.ReplaceAll(strings.TrimSpace(string(certPEM)), "\n", " ")
		assert.Equal(t, want, CertificateFingerprint([]byte(collapsed)))
	})

	t.Run("not PEM", func(t *testing.T) {
		assert.Empty(t, CertificateFingerprint([]byte("not a certificate")))
		assert.Empty(t, PublicKeyFingerprint([]byte("not a key")))
	})
}

func TestIsStoreID(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)

	assert.True(t, IsStoreID(fingerprint))
	assert.True(t, IsStoreID("5f0c1a2b3c4d5e6f708192a3"+fingerprint))
	assert.True(t, IsStoreID("default"+fingerprint), "org IDs aren't always hex")
	assert.False(t, IsStoreID("/etc/tyk/"+fingerprint))
	assert.False(t, IsStoreID("/etc/tyk/upstream.pem"))
	assert.False(t, IsStoreID("cert"))
	assert.False(t, IsStoreID(""))
}
