package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPublicKey(t *testing.T) {
	tests := []struct {
		name string
		cert *tls.Certificate
		want bool
	}{
		{
			name: "nil leaf",
			cert: &tls.Certificate{Leaf: nil},
			want: false,
		},
		{
			name: "non public key",
			cert: &tls.Certificate{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "Non-Public Key: "}}},
			want: false,
		},
		{
			name: "public key",
			cert: &tls.Certificate{Leaf: PrefixPublicKeyCommonName([]byte("dummy-value"))},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicKey(tt.cert); got != tt.want {
				t.Errorf("IsPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRSAPublicKey(t *testing.T) {
	pubKey := GenerateRSAPublicKey(t)
	assert.Contains(t, string(pubKey), "PUBLIC KEY")
}

func TestAddCACertificatesFromChainToPool(t *testing.T) {
	t.Run("nil pool", func(t *testing.T) {
		// Should not panic with nil pool
		_, _, _, cert := GenCertificate(&x509.Certificate{}, false)
		AddCACertificatesFromChainToPool(nil, &cert)
	})

	t.Run("nil certificate", func(t *testing.T) {
		// Should not panic with nil certificate
		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, nil)
	})

	t.Run("single certificate without chain - not a CA", func(t *testing.T) {
		// Create a single leaf certificate (no CA in chain, IsCA=false)
		// This represents a pinned certificate for certificate pinning use cases
		_, _, _, cert := GenCertificate(&x509.Certificate{
			Subject: pkix.Name{CommonName: "leaf"},
			IsCA:    false,
		}, false)

		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, &cert)

		// Pool should contain 1 certificate for backward compatibility and certificate pinning
		assert.Equal(t, 1, len(pool.Subjects()))
	})

	t.Run("single certificate with IsCA=true", func(t *testing.T) {
		// Create a single self-signed CA certificate
		_, _, _, cert := GenCertificate(&x509.Certificate{
			Subject: pkix.Name{CommonName: "Self-Signed CA"},
			IsCA:    true,
		}, false)

		// Verify it's a single cert
		assert.Equal(t, 1, len(cert.Certificate))

		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, &cert)

		// Pool should contain 1 certificate (the CA at index 0)
		assert.Equal(t, 1, len(pool.Subjects()))
	})

	t.Run("certificate chain with CA", func(t *testing.T) {
		// Generate root CA
		rootCertPEM, rootKeyPEM, err := GenerateRootCertAndKey(t)
		assert.NoError(t, err)

		// Generate client cert with chain (includes root CA)
		clientCertChainPEM, clientKeyPEM, err := GenerateClientCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)

		// Load the certificate chain
		clientCert, err := tls.X509KeyPair(clientCertChainPEM.Bytes(), clientKeyPEM.Bytes())
		assert.NoError(t, err)

		// The chain should have 2 certificates: [0] = leaf, [1] = CA
		assert.Equal(t, 2, len(clientCert.Certificate))

		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, &clientCert)

		// Pool should contain 1 CA certificate
		assert.Equal(t, 1, len(pool.Subjects()))
	})

	t.Run("leaf certificate is not added to pool", func(t *testing.T) {
		// Generate root CA
		rootCertPEM, rootKeyPEM, err := GenerateRootCertAndKey(t)
		assert.NoError(t, err)

		// Generate client cert with chain
		clientCertChainPEM, clientKeyPEM, err := GenerateClientCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)

		// Load the certificate chain
		clientCert, err := tls.X509KeyPair(clientCertChainPEM.Bytes(), clientKeyPEM.Bytes())
		assert.NoError(t, err)

		// Parse the leaf certificate
		leafCert, err := x509.ParseCertificate(clientCert.Certificate[0])
		assert.NoError(t, err)
		assert.False(t, leafCert.IsCA, "Leaf should not be a CA")

		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, &clientCert)

		// Verify that the pool does not contain the leaf certificate
		// by checking that the subjects don't match the leaf's subject
		subjects := pool.Subjects()
		for _, subject := range subjects {
			cert := &x509.Certificate{RawSubject: subject}
			assert.NotEqual(t, leafCert.Subject.String(), cert.Subject.String())
		}
	})

	t.Run("only CA certificates are added", func(t *testing.T) {
		// Generate root CA
		rootCertPEM, rootKeyPEM, err := GenerateRootCertAndKey(t)
		assert.NoError(t, err)

		// Generate server cert with chain
		serverCertChainPEM, serverKeyPEM, err := GenerateServerCertAndKeyChain(t, rootCertPEM, rootKeyPEM)
		assert.NoError(t, err)

		// Load the certificate chain
		serverCert, err := tls.X509KeyPair(serverCertChainPEM.Bytes(), serverKeyPEM.Bytes())
		assert.NoError(t, err)

		// Verify the chain structure
		assert.GreaterOrEqual(t, len(serverCert.Certificate), 2)

		// Parse all certs in the chain
		leafCert, err := x509.ParseCertificate(serverCert.Certificate[0])
		assert.NoError(t, err)
		assert.False(t, leafCert.IsCA, "Index 0 should be leaf (not CA)")

		caCert, err := x509.ParseCertificate(serverCert.Certificate[1])
		assert.NoError(t, err)
		assert.True(t, caCert.IsCA, "Index 1 should be CA")

		pool := x509.NewCertPool()
		AddCACertificatesFromChainToPool(pool, &serverCert)

		// Only CA cert should be in pool
		assert.Equal(t, 1, len(pool.Subjects()))
	})

	t.Run("malformed certificate in chain", func(t *testing.T) {
		// Create a certificate with a malformed cert in the chain
		cert := &tls.Certificate{
			Certificate: [][]byte{
				{0x01, 0x02, 0x03}, // Valid-looking leaf (index 0, will be skipped anyway)
				{0xFF, 0xFF, 0xFF}, // Malformed cert at index 1
			},
		}

		pool := x509.NewCertPool()
		// Should not panic, just log error and continue
		AddCACertificatesFromChainToPool(pool, cert)

		// Pool should be empty since the only cert in chain (besides leaf) was malformed
		assert.Equal(t, 0, len(pool.Subjects()))
	})
}
