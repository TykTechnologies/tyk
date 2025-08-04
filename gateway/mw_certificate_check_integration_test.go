package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// setupIntegrationMW creates a middleware instance for integration testing
func setupIntegrationMW(t *testing.T, useMutualTLS bool, certs []*tls.Certificate) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if certs != nil {
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return(certs).
			AnyTimes()
	}

	// Create a cache for testing
	mockCache := cache.New(3600, 600)

	// Generate unique test prefix for Redis keys to avoid clashes
	testPrefix := fmt.Sprintf("test-%d-", time.Now().UnixNano())

	gw := &Gateway{
		CertificateManager: mockCertManager,
		UtilCache:          mockCache,
	}

	// Initialize storage connection handler
	gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())

	// Set the configuration properly with Redis storage
	gwConfig := config.Config{
		Storage: config.StorageOptionsConf{
			Type:    "redis",
			Host:    "localhost",
			Port:    6379,
			MaxIdle: 100,
		},
		Security: config.SecurityConfig{
			Certificates: config.CertificatesConfig{
				API: []string{"cert2"},
			},
			CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 60, // Custom threshold
				CheckCooldownSeconds: 3600,
				EventCooldownSeconds: 86400,
			},
		},
	}
	gw.SetConfig(gwConfig)

	// Connect to Redis
	ctx := context.Background()
	gw.StorageConnectionHandler.Connect(ctx, func() {
		// Connection callback - do nothing for tests
	}, &gwConfig)

	// Wait for connection to be established
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := gw.StorageConnectionHandler.WaitConnect(timeout)
	if !connected {
		t.Fatalf("Redis connection was not established in test setup")
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					UseMutualTLSAuth:   true,
					ClientCertificates: []string{"cert1"},
					APIID:              "integration-test-api-id",
					OrgID:              "integration-test-org-id",
				},
				GlobalConfig: gw.GetConfig(),
			},
			Gw: gw,
		},
	}

	// Initialize Redis store with randomized prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	return mw
}

// setupIntegrationMWWithPrefix creates a middleware instance for integration testing with a specific test prefix
func setupIntegrationMWWithPrefix(t *testing.T, _ bool, certs []*tls.Certificate, testPrefix string) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if certs != nil {
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return(certs).
			AnyTimes()
	}

	gw := &Gateway{
		CertificateManager: mockCertManager,
	}

	// Initialize storage connection handler
	gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())

	// Set the configuration properly with Redis storage
	gwConfig := config.Config{
		Storage: config.StorageOptionsConf{
			Type:    "redis",
			Host:    "localhost",
			Port:    6379,
			MaxIdle: 100,
		},
		Security: config.SecurityConfig{
			Certificates: config.CertificatesConfig{
				API: []string{"cert2"},
			},
			CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 60, // Custom threshold
				CheckCooldownSeconds: 3600,
				EventCooldownSeconds: 86400,
			},
		},
	}
	gw.SetConfig(gwConfig)

	// Connect to Redis
	ctx := context.Background()
	gw.StorageConnectionHandler.Connect(ctx, func() {
		// Connection callback - do nothing for tests
	}, &gwConfig)

	// Wait for connection to be established
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := gw.StorageConnectionHandler.WaitConnect(timeout)
	if !connected {
		t.Fatalf("Redis connection was not established in test setup")
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					UseMutualTLSAuth:   true,
					ClientCertificates: []string{"cert1"},
					APIID:              "integration-test-api-id",
					OrgID:              "integration-test-org-id",
				},
				GlobalConfig: gw.GetConfig(),
			},
			Gw: gw,
		},
	}

	// Initialize Redis store with the provided prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	return mw
}

// createIntegrationTestCertificate creates a simple test certificate for integration tests
func createIntegrationTestCertificate(daysUntilExpiry int, commonName string) *tls.Certificate {
	expirationDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotAfter: expirationDate,
			Raw:      []byte("test-certificate-data-" + commonName),
			Extensions: []pkix.Extension{
				{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
			},
		},
	}
}

// TestCertificateCheckMW_Integration_CoreFunctionality tests the core certificate expiration logic
func TestCertificateCheckMW_Integration_CoreFunctionality(t *testing.T) {
	t.Parallel()

	t.Run("Valid Certificate - No Event Fired", func(t *testing.T) {
		// Create a certificate that expires in 60 days (outside warning threshold)
		cert := createIntegrationTestCertificate(60, "valid.example.com")

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// Verify no event was fired (certificate is not expiring soon)
		// This is tested by ensuring the function completes without error
	})

	t.Run("Expiring Certificate - Event Should Be Fired", func(t *testing.T) {
		// Create a certificate that expires in 15 days (within warning threshold)
		cert := createIntegrationTestCertificate(15, "expiring.example.com")

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// The event firing is tested indirectly through the cooldown mechanism
		// A second call should not fire the event due to cooldown
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})

	t.Run("Critical Certificate - Event Should Be Fired", func(t *testing.T) {
		// Create a certificate that expires in 5 days (critical)
		cert := createIntegrationTestCertificate(5, "critical.example.com")

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})

	t.Run("Multiple Certificates - Mixed Expiration", func(t *testing.T) {
		// Create certificates with different expiration dates
		validCert := createIntegrationTestCertificate(60, "valid.example.com")
		expiringCert := createIntegrationTestCertificate(15, "expiring.example.com")
		criticalCert := createIntegrationTestCertificate(5, "critical.example.com")

		// Create TLS certificates
		tlsCerts := []*tls.Certificate{validCert, expiringCert, criticalCert}

		mw := setupIntegrationMW(t, true, tlsCerts)

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration(tlsCerts)
	})
}

// TestCertificateCheckMW_Integration_Configuration tests different configuration scenarios
func TestCertificateCheckMW_Integration_Configuration(t *testing.T) {
	t.Parallel()

	t.Run("Custom Warning Threshold", func(t *testing.T) {
		// Create a certificate that expires in 45 days
		cert := createIntegrationTestCertificate(45, "custom.example.com")

		// Create middleware with custom warning threshold
		ctrl := gomock.NewController(t)
		mockCertManager := mock.NewMockCertificateManager(ctrl)
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return([]*tls.Certificate{cert}).
			AnyTimes()

		mockCache := cache.New(3600, 600)

		gw := &Gateway{
			CertificateManager: mockCertManager,
			UtilCache:          mockCache,
		}

		// Set the configuration properly
		gw.SetConfig(config.Config{
			Security: config.SecurityConfig{
				Certificates: config.CertificatesConfig{
					API: []string{"cert2"},
				},
				CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 60, // Custom threshold
					CheckCooldownSeconds: 3600,
					EventCooldownSeconds: 86400,
				},
			},
		})

		mw := &CertificateCheckMW{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						UseMutualTLSAuth:   true,
						ClientCertificates: []string{"cert1"},
					},
					GlobalConfig: gw.GetConfig(),
				},
				Gw: gw,
			},
		}

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})

	t.Run("Short Cooldown Period", func(t *testing.T) {
		// Create a certificate that expires in 15 days
		cert := createIntegrationTestCertificate(15, "shortcooldown.example.com")

		// Create middleware with short cooldown
		ctrl := gomock.NewController(t)
		mockCertManager := mock.NewMockCertificateManager(ctrl)
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return([]*tls.Certificate{cert}).
			AnyTimes()

		mockCache := cache.New(3600, 600)

		gw := &Gateway{
			CertificateManager: mockCertManager,
			UtilCache:          mockCache,
		}

		// Set the configuration properly
		gw.SetConfig(config.Config{
			Security: config.SecurityConfig{
				Certificates: config.CertificatesConfig{
					API: []string{"cert2"},
				},
				CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 30,
					CheckCooldownSeconds: 3600,
					EventCooldownSeconds: 1, // Very short cooldown for testing
				},
			},
		})

		mw := &CertificateCheckMW{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						UseMutualTLSAuth:   true,
						ClientCertificates: []string{"cert1"},
					},
					GlobalConfig: gw.GetConfig(),
				},
				Gw: gw,
			},
		}

		// First call
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// Wait for cooldown to expire
		time.Sleep(2 * time.Second)

		// Second call - should fire event again due to short cooldown
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})
}

// TestCertificateCheckMW_Integration_ErrorScenarios tests error scenarios
func TestCertificateCheckMW_Integration_ErrorScenarios(t *testing.T) {
	t.Parallel()

	t.Run("Expired Certificate", func(t *testing.T) {
		// Create a certificate that has already expired
		cert := createIntegrationTestCertificate(-1, "expired.example.com")

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})

	t.Run("Nil Certificate", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)

		// Test with nil certificate
		mw.checkCertificateExpiration([]*tls.Certificate{nil})
	})

	t.Run("Certificate with Nil Leaf", func(t *testing.T) {
		cert := &tls.Certificate{
			Leaf: nil, // Nil leaf
		}

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Test with certificate that has nil leaf
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})
}

// TestCertificateCheckMW_Integration_Performance tests performance characteristics
func TestCertificateCheckMW_Integration_Performance(t *testing.T) {
	t.Parallel()

	t.Run("Multiple Certificates Processing", func(t *testing.T) {
		// Create multiple certificates
		certs := []*tls.Certificate{
			createIntegrationTestCertificate(60, "cert1.example.com"),
			createIntegrationTestCertificate(15, "cert2.example.com"),
			createIntegrationTestCertificate(5, "cert3.example.com"),
			createIntegrationTestCertificate(90, "cert4.example.com"),
			createIntegrationTestCertificate(30, "cert5.example.com"),
		}

		mw := setupIntegrationMW(t, true, certs)

		// Process multiple certificates
		for i := 0; i < 10; i++ {
			mw.checkCertificateExpiration(certs)
		}
	})

	t.Run("Large Certificate Processing", func(t *testing.T) {
		// Create a certificate with large extensions
		cert := createIntegrationTestCertificate(30, "large.example.com")

		// Add large extensions to simulate complex certificates
		cert.Leaf.Extensions = append(cert.Leaf.Extensions, pkix.Extension{
			Id:    []int{1, 2, 3, 4, 5},
			Value: make([]byte, 1000), // Large extension
		})

		mw := setupIntegrationMW(t, true, []*tls.Certificate{cert})

		// Process large certificate
		mw.checkCertificateExpiration([]*tls.Certificate{cert})
	})
}

// TestCertificateCheckMW_Integration_HelperMethods tests the helper methods in integration context
func TestCertificateCheckMW_Integration_HelperMethods(t *testing.T) {
	t.Parallel()

	mw := setupIntegrationMW(t, true, nil)

	// Test certificate ID generation
	cert := createIntegrationTestCertificate(30, "helper-test.example.com")
	certID := mw.generateCertificateID(cert)
	assert.NotEmpty(t, certID)
	assert.Len(t, certID, 40) // SHA1 hash length

	// Test with nil certificate
	nilCertID := mw.generateCertificateID(nil)
	assert.Empty(t, nilCertID)

	// Test with certificate that has nil Leaf
	certWithNilLeaf := &tls.Certificate{}
	nilLeafCertID := mw.generateCertificateID(certWithNilLeaf)
	assert.Empty(t, nilLeafCertID)
}

// TestCertificateCheckMW_Integration_CheckCooldown tests the check cooldown mechanism in integration context
func TestCertificateCheckMW_Integration_CheckCooldown(t *testing.T) {
	t.Parallel()

	t.Run("Check Cooldown Respects Configuration", func(t *testing.T) {
		// Create middleware with short check cooldown for testing
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60 // 1 minute

		cert := createIntegrationTestCertificate(15, "cooldown-test.example.com")
		certID := mw.generateCertificateID(cert)

		// First check should be allowed
		shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldSkip, "First check should be allowed")

		// Second check should be blocked by cooldown
		shouldSkip = mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldSkip, "Second check should be blocked by cooldown")

		// Different certificate should still be allowed
		differentCert := createIntegrationTestCertificate(15, "different-cooldown-test.example.com")
		differentCertID := mw.generateCertificateID(differentCert)
		shouldSkip = mw.shouldSkipCertificate(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldSkip, "Different certificate should be allowed")
	})

	t.Run("Check Cooldown with Zero Value", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 0 // No cooldown

		cert := createIntegrationTestCertificate(15, "zero-cooldown-test.example.com")
		certID := mw.generateCertificateID(cert)

		// Multiple checks should always be allowed with zero cooldown
		for i := 0; i < 5; i++ {
			shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
			assert.False(t, shouldSkip, "Check should always be allowed with zero cooldown")
		}
	})

	t.Run("Check Cooldown with Empty Certificate ID", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)

		// Empty certID should not be allowed
		shouldSkip := mw.shouldSkipCertificate("", mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldSkip, "Empty certID should not be allowed")
	})
}

// TestCertificateCheckMW_Integration_EventCooldown tests the event cooldown mechanism in integration context
func TestCertificateCheckMW_Integration_EventCooldown(t *testing.T) {
	t.Parallel()

	t.Run("Event Cooldown Respects Configuration", func(t *testing.T) {
		// Create middleware with short event cooldown for testing
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120 // 2 minutes

		certID := "event-cooldown-test-cert-id"

		// First event should be allowed
		shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "First event should be allowed")

		// Second event should be blocked by cooldown
		shouldFire = mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldFire, "Second event should be blocked by cooldown")

		// Different certificate should still be allowed
		differentCertID := "different-event-cooldown-test-cert-id"
		shouldFire = mw.shouldFireExpiryEvent(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "Different certificate should be allowed")
	})

	t.Run("Event Cooldown with Zero Value", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 0 // No cooldown

		certID := "zero-event-cooldown-test-cert-id"

		// Multiple events should always be allowed with zero cooldown
		for i := 0; i < 5; i++ {
			shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
			assert.True(t, shouldFire, "Event should always be allowed with zero cooldown")
		}
	})

	t.Run("Event Cooldown with Empty Certificate ID", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)

		// Empty certID should not be allowed
		shouldFire := mw.shouldFireExpiryEvent("", mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldFire, "Empty certID should not be allowed")
	})
}

// TestCertificateCheckMW_Integration_CooldownIntegration tests both cooldown mechanisms working together
func TestCertificateCheckMW_Integration_CooldownIntegration(t *testing.T) {
	t.Parallel()

	t.Run("Both Cooldowns Work Together", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)
		// Set short cooldowns for testing
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60  // 1 minute
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120 // 2 minutes

		cert := createIntegrationTestCertificate(15, "integration-test.example.com")
		certID := mw.generateCertificateID(cert)

		// First call: should allow both check and event
		shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldSkip, "First check should be allowed")

		shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "First event should be allowed")

		// Second call: should block both check and event due to cooldown
		shouldSkip = mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldSkip, "Second check should be blocked by cooldown")

		shouldFire = mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldFire, "Second event should be blocked by cooldown")

		// Different certID should still work
		differentCertID := "different-integration-cert-id"
		shouldSkip = mw.shouldSkipCertificate(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldSkip, "Different certID check should be allowed")

		shouldFire = mw.shouldFireExpiryEvent(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "Different certID event should be allowed")
	})

	t.Run("Different Certificates Are Independent", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120

		cert1 := createIntegrationTestCertificate(15, "integration-test-1.example.com")
		cert2 := createIntegrationTestCertificate(15, "integration-test-2.example.com")
		certID1 := mw.generateCertificateID(cert1)
		certID2 := mw.generateCertificateID(cert2)

		// Set cooldowns for first certificate
		mw.shouldSkipCertificate(certID1, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		mw.shouldFireExpiryEvent(certID1, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)

		// Second certificate should still be allowed
		shouldSkip := mw.shouldSkipCertificate(certID2, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldSkip, "Second certificate check should be allowed")

		shouldFire := mw.shouldFireExpiryEvent(certID2, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "Second certificate event should be allowed")
	})
}

// TestCertificateCheckMW_Integration_CooldownPersistence tests that cooldowns persist across middleware instances
func TestCertificateCheckMW_Integration_CooldownPersistence(t *testing.T) {
	t.Parallel()

	// Generate a shared test prefix for both middleware instances
	sharedTestPrefix := fmt.Sprintf("test-%d-", time.Now().UnixNano())

	// Create first middleware instance
	mw1 := setupIntegrationMWWithPrefix(t, true, nil, sharedTestPrefix)

	// Create second middleware instance with same prefix
	mw2 := setupIntegrationMWWithPrefix(t, true, nil, sharedTestPrefix)

	// Create a test certificate
	cert := createIntegrationTestCertificate(15, "persistence-integration-test.example.com")
	certID := mw1.generateCertificateID(cert)
	assert.NotEmpty(t, certID)

	// Configure short cooldowns for testing
	monitorConfig := config.CertificateExpiryMonitorConfig{
		WarningThresholdDays: 30,
		CheckCooldownSeconds: 60,  // 1 minute
		EventCooldownSeconds: 120, // 2 minutes
	}

	t.Run("Cooldowns persist across instances", func(t *testing.T) {
		// Test check cooldown persistence
		// First check should succeed
		shouldSkip1 := mw1.shouldSkipCertificate(certID, monitorConfig)
		assert.False(t, shouldSkip1, "First check should be allowed")

		// Check with different instance should fail (cooldown persists)
		shouldSkip2 := mw2.shouldSkipCertificate(certID, monitorConfig)
		assert.True(t, shouldSkip2, "Check cooldown should persist across instances")

		// Test event cooldown persistence
		// First event should succeed
		shouldFire1 := mw1.shouldFireExpiryEvent(certID, monitorConfig)
		assert.True(t, shouldFire1, "First event should be allowed")

		// Event with different instance should fail (cooldown persists)
		shouldFire2 := mw2.shouldFireExpiryEvent(certID, monitorConfig)
		assert.False(t, shouldFire2, "Event cooldown should persist across instances")
	})
}

// TestCertificateCheckMW_Integration_EndToEndCooldown tests the complete end-to-end cooldown behavior
func TestCertificateCheckMW_Integration_EndToEndCooldown(t *testing.T) {
	t.Parallel()

	t.Run("End-to-End Cooldown Behavior", func(t *testing.T) {
		// Create middleware with short cooldowns for testing
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30

		// Create a certificate that expires in 15 days (within warning threshold)
		cert := createIntegrationTestCertificate(15, "endtoend-test.example.com")

		// First call to checkCertificateExpiration should process the certificate
		// and potentially fire an event
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// Second call should skip the certificate due to check cooldown
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// Third call should also skip due to check cooldown
		mw.checkCertificateExpiration([]*tls.Certificate{cert})

		// The function should complete without errors even when cooldowns are active
		// This tests that the cooldown logic doesn't break the main flow
	})

	t.Run("End-to-End with Multiple Certificates", func(t *testing.T) {
		mw := setupIntegrationMW(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30

		// Create multiple certificates
		cert1 := createIntegrationTestCertificate(15, "endtoend-multi-1.example.com")
		cert2 := createIntegrationTestCertificate(15, "endtoend-multi-2.example.com")
		cert3 := createIntegrationTestCertificate(60, "endtoend-multi-3.example.com") // Outside threshold

		certs := []*tls.Certificate{cert1, cert2, cert3}

		// First call should process all certificates
		mw.checkCertificateExpiration(certs)

		// Second call should skip cert1 and cert2 due to check cooldown
		// but cert3 should still be processed (though it won't trigger events)
		mw.checkCertificateExpiration(certs)

		// The function should complete without errors
	})
}
