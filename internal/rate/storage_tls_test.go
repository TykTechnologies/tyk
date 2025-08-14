package rate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTLSConfig(t *testing.T) {
	t.Run("No SSL configured", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL: false,
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("SSL with InsecureSkipVerify", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL:                true,
			SSLInsecureSkipVerify: true,
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.True(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("SSL with TLS versions", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL:        true,
			TLSMinVersion: "1.2",
			TLSMaxVersion: "1.3",
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion)
	})

	t.Run("SSL with invalid TLS version", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL:        true,
			TLSMinVersion: "invalid",
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Equal(t, uint16(0), tlsConfig.MinVersion) // Should be zero for invalid version
	})

	t.Run("SSL with CA certificate", func(t *testing.T) {
		// Create a temporary CA certificate
		tempDir := t.TempDir()
		caFile := filepath.Join(tempDir, "ca.crt")
		createTestCACert(t, caFile)

		cfg := &config.StorageOptionsConf{
			UseSSL: true,
			CAFile: caFile,
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.RootCAs)
	})

	t.Run("SSL with invalid CA certificate path", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL: true,
			CAFile: "/nonexistent/ca.crt",
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Nil(t, tlsConfig.RootCAs) // Should be nil when CA loading fails
	})

	t.Run("SSL with client certificate and key", func(t *testing.T) {
		// Create temporary client certificate and key
		tempDir := t.TempDir()
		certFile := filepath.Join(tempDir, "client.crt")
		keyFile := filepath.Join(tempDir, "client.key")
		createTestCertAndKey(t, certFile, keyFile)

		cfg := &config.StorageOptionsConf{
			UseSSL:   true,
			CertFile: certFile,
			KeyFile:  keyFile,
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("SSL with only cert file (missing key)", func(t *testing.T) {
		tempDir := t.TempDir()
		certFile := filepath.Join(tempDir, "client.crt")
		createTestCACert(t, certFile) // Just create a cert file

		cfg := &config.StorageOptionsConf{
			UseSSL:   true,
			CertFile: certFile,
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 0) // Should be empty when key is missing
	})

	t.Run("SSL with invalid client certificate path", func(t *testing.T) {
		cfg := &config.StorageOptionsConf{
			UseSSL:   true,
			CertFile: "/nonexistent/client.crt",
			KeyFile:  "/nonexistent/client.key",
		}
		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.Len(t, tlsConfig.Certificates, 0) // Should be empty when loading fails
	})

	t.Run("SSL with full mTLS configuration", func(t *testing.T) {
		// Create all certificates
		tempDir := t.TempDir()
		caFile := filepath.Join(tempDir, "ca.crt")
		certFile := filepath.Join(tempDir, "client.crt")
		keyFile := filepath.Join(tempDir, "client.key")

		createTestCACert(t, caFile)
		createTestCertAndKey(t, certFile, keyFile)

		cfg := &config.StorageOptionsConf{
			UseSSL:                true,
			SSLInsecureSkipVerify: false,
			CAFile:                caFile,
			CertFile:              certFile,
			KeyFile:               keyFile,
			TLSMinVersion:         "1.2",
			TLSMaxVersion:         "1.3",
		}

		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.False(t, tlsConfig.InsecureSkipVerify)
		assert.NotNil(t, tlsConfig.RootCAs)
		assert.Len(t, tlsConfig.Certificates, 1)
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion)
	})

	t.Run("SSL with partial failures still applies other settings", func(t *testing.T) {
		// Test that even if CA loading fails, other TLS settings are still applied
		tempDir := t.TempDir()
		certFile := filepath.Join(tempDir, "client.crt")
		keyFile := filepath.Join(tempDir, "client.key")
		createTestCertAndKey(t, certFile, keyFile)

		cfg := &config.StorageOptionsConf{
			UseSSL:                true,
			SSLInsecureSkipVerify: true,
			CAFile:                "/nonexistent/ca.crt", // This will fail to load
			CertFile:              certFile,              // But this should still work
			KeyFile:               keyFile,
			TLSMinVersion:         "1.2",
			TLSMaxVersion:         "1.3",
		}

		tlsConfig := createTLSConfig(cfg)
		assert.NotNil(t, tlsConfig)
		assert.True(t, tlsConfig.InsecureSkipVerify)
		assert.Nil(t, tlsConfig.RootCAs)                                // CA loading failed
		assert.Len(t, tlsConfig.Certificates, 1)                        // But client cert still loaded
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion) // And TLS versions still set
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion)
	})
}

func TestGetTLSVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
		ok       bool
	}{
		{"1.0", tls.VersionTLS10, true},
		{"1.1", tls.VersionTLS11, true},
		{"1.2", tls.VersionTLS12, true},
		{"1.3", tls.VersionTLS13, true},
		{"invalid", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			version, ok := getTLSVersion(tt.input)
			assert.Equal(t, tt.expected, version)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

// Helper function to create a test CA certificate
func createTestCACert(t *testing.T, filename string) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	err = os.WriteFile(filename, certPEM, 0644)
	require.NoError(t, err)
}

// Helper function to create a test client certificate and key
func createTestCertAndKey(t *testing.T, certFile, keyFile string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	err = os.WriteFile(certFile, certPEM, 0644)
	require.NoError(t, err)

	err = os.WriteFile(keyFile, keyPEM, 0600)
	require.NoError(t, err)
}
