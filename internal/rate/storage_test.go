package rate

import (
	"crypto/tls"
	"errors"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func TestNewStorage(t *testing.T) {
	conf, err := config.NewDefaultWithEnv()
	assert.NoError(t, err)

	// Coverage
	conf.Storage.MaxActive = 100
	conf.Storage.Timeout = 4
	conf.Storage.UseSSL = true

	client, err := NewStorage(&conf.Storage)
	assert.NotNil(t, client)
	assert.NoError(t, err)

	conf.Storage.EnableCluster = true
	client, err = NewStorage(&conf.Storage)
	assert.NotNil(t, client)
	assert.NoError(t, err)

	conf.Storage.EnableCluster = false
	conf.Storage.MasterName = "redis"
	client, err = NewStorage(&conf.Storage)
	assert.NotNil(t, client)
	assert.NoError(t, err)
}

func TestNewStorageWithTLS(t *testing.T) {
	baseConfig, err := config.NewDefaultWithEnv()
	assert.NoError(t, err)

	tests := []struct {
		name           string
		configModifier func(*config.StorageOptionsConf) // Function to modify the base config
		expectError    bool
		errorSubstring string
	}{
		{
			name: "Valid TLS versions",
			configModifier: func(cfg *config.StorageOptionsConf) {
				cfg.UseSSL = true
				cfg.TLSMinVersion = "1.2"
				cfg.TLSMaxVersion = "1.3"
			},
			expectError: false,
		},
		{
			name: "Min version higher than max version",
			configModifier: func(cfg *config.StorageOptionsConf) {
				cfg.UseSSL = true
				cfg.TLSMinVersion = "1.3"
				cfg.TLSMaxVersion = "1.2"
			},
			expectError:    true,
			errorSubstring: "MinVersion is higher than MaxVersion",
		},
		{
			name: "Invalid min version",
			configModifier: func(cfg *config.StorageOptionsConf) {
				cfg.UseSSL = true
				cfg.TLSMinVersion = "invalid"
			},
			expectError:    true,
			errorSubstring: InvalidTLSMinVersion.Error(),
		},
		{
			name: "Invalid max version",
			configModifier: func(cfg *config.StorageOptionsConf) {
				cfg.UseSSL = true
				cfg.TLSMaxVersion = "invalid"
			},
			expectError:    true,
			errorSubstring: InvalidTLSMaxVersion.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start with a fresh copy of the base configuration
			testConfig := baseConfig

			// Apply the test-specific modifications
			if tt.configModifier != nil {
				tt.configModifier(&testConfig.Storage)
			}

			client, err := NewStorage(&testConfig.Storage)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
				assert.Nil(t, client, "Client should be nil when there's an error")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client, "Client should not be nil when there's no error")
			}
		})
	}
}

func TestHandleTLSVersion(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.StorageOptionsConf
		wantMin int
		wantMax int
		wantErr error
	}{
		{
			name:    "defaults applied",
			cfg:     config.StorageOptionsConf{},
			wantMin: tls.VersionTLS12,
			wantMax: tls.VersionTLS13,
			wantErr: nil,
		},
		{
			name: "valid explicit versions",
			cfg: config.StorageOptionsConf{
				TLSMinVersion: "1.1",
				TLSMaxVersion: "1.2",
			},
			wantMin: tls.VersionTLS11,
			wantMax: tls.VersionTLS12,
			wantErr: nil,
		},
		{
			name: "invalid max version",
			cfg: config.StorageOptionsConf{
				TLSMaxVersion: "2.0",
			},
			wantErr: InvalidTLSMaxVersion,
		},
		{
			name: "invalid min version",
			cfg: config.StorageOptionsConf{
				TLSMinVersion: "0.9",
			},
			wantErr: InvalidTLSMinVersion,
		},
		{
			name: "min greater than max",
			cfg: config.StorageOptionsConf{
				TLSMinVersion: "1.3",
				TLSMaxVersion: "1.2",
			},
			wantErr: InvalidTLSVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minV, maxV, err := handleTLSVersion(&tt.cfg)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected err %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if minV != tt.wantMin {
				t.Errorf("minVersion: expected %v, got %v", tt.wantMin, minV)
			}
			if maxV != tt.wantMax {
				t.Errorf("maxVersion: expected %v, got %v", tt.wantMax, maxV)
			}
		})
	}
}

func TestLoadTLSConfig(t *testing.T) {
	// Create a temporary directory for our test certificates
	tempDir, err := os.MkdirTemp("", "tls-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate root certificate and key
	rootCertPEM, rootKeyPEM, err := crypto.GenerateRootCertAndKey(t)
	require.NoError(t, err)

	// Generate server certificate and key
	serverCertPEM, serverKeyPEM, err := crypto.GenerateServerCertAndKeyPEM(t, rootCertPEM, rootKeyPEM)
	require.NoError(t, err)

	// Write certificates and keys to files
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	caFile := filepath.Join(tempDir, "ca.pem")

	require.NoError(t, os.WriteFile(certFile, serverCertPEM.Bytes(), 0644))
	require.NoError(t, os.WriteFile(keyFile, serverKeyPEM.Bytes(), 0644))
	require.NoError(t, os.WriteFile(caFile, rootCertPEM, 0644))

	tests := []struct {
		name           string
		config         *config.StorageOptionsConf
		expectError    bool
		errorSubstring string
		checkFunc      func(*testing.T, *tls.Config)
	}{
		{
			name: "TLS disabled",
			config: &config.StorageOptionsConf{
				UseSSL: false,
			},
			expectError: false,
			checkFunc: func(t *testing.T, c *tls.Config) {
				assert.Nil(t, c, "TLS config should be nil when TLS is disabled")
			},
		},
		{
			name: "Basic TLS config",
			config: &config.StorageOptionsConf{
				UseSSL:                true,
				SSLInsecureSkipVerify: true,
			},
			expectError: false,
			checkFunc: func(t *testing.T, c *tls.Config) {
				assert.NotNil(t, c, "TLS config should not be nil")
				assert.True(t, c.InsecureSkipVerify, "InsecureSkipVerify should be true")
			},
		},
		{
			name: "TLS with certificates",
			config: &config.StorageOptionsConf{
				UseSSL:   true,
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   caFile,
			},
			expectError: false,
			checkFunc: func(t *testing.T, c *tls.Config) {
				assert.NotNil(t, c, "TLS config should not be nil")
				assert.Len(t, c.Certificates, 1, "Should have 1 certificate")
				assert.NotNil(t, c.RootCAs, "RootCAs should not be nil")
			},
		},
		{
			name: "TLS with invalid certificate path",
			config: &config.StorageOptionsConf{
				UseSSL:   true,
				CertFile: "nonexistent.crt",
				KeyFile:  keyFile,
			},
			expectError:    true,
			errorSubstring: "no such file or directory",
		},
		{
			name: "TLS with invalid key path",
			config: &config.StorageOptionsConf{
				UseSSL:   true,
				CertFile: certFile,
				KeyFile:  "nonexistent.key",
			},
			expectError:    true,
			errorSubstring: "no such file or directory",
		},
		{
			name: "TLS with invalid CA path",
			config: &config.StorageOptionsConf{
				UseSSL: true,
				CAFile: "nonexistent.ca",
			},
			expectError:    true,
			errorSubstring: "no such file or directory",
		},
		{
			name: "TLS with valid min and max versions",
			config: &config.StorageOptionsConf{
				UseSSL:        true,
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
			},
			expectError: false,
			checkFunc: func(t *testing.T, c *tls.Config) {
				assert.NotNil(t, c, "TLS config should not be nil")
				assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion, "MinVersion should be TLS 1.2")
				assert.Equal(t, uint16(tls.VersionTLS13), c.MaxVersion, "MaxVersion should be TLS 1.3")
			},
		},
		{
			name: "TLS with invalid min version",
			config: &config.StorageOptionsConf{
				UseSSL:        true,
				TLSMinVersion: "invalid",
			},
			expectError:    true,
			errorSubstring: "invalid MinVersion specified",
		},
		{
			name: "TLS with invalid max version",
			config: &config.StorageOptionsConf{
				UseSSL:        true,
				TLSMaxVersion: "invalid",
			},
			expectError:    true,
			errorSubstring: "invalid MaxVersion specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := loadTLSConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
			} else {
				assert.NoError(t, err)
				if tt.checkFunc != nil {
					tt.checkFunc(t, tlsConfig)
				}
			}
		})
	}
}
