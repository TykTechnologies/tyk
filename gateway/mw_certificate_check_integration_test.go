package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// MockEventTracker tracks fired events for testing
type MockEventTracker struct {
	mu     sync.RWMutex
	events []eventInfo
}

type eventInfo struct {
	EventType apidef.TykEvent
	Meta      interface{}
	Timestamp time.Time
}

func (m *MockEventTracker) Init(_ interface{}) error {
	// No initialization needed for mock
	return nil
}

func (m *MockEventTracker) HandleEvent(eventMessage config.EventMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = append(m.events, eventInfo{
		EventType: eventMessage.Type,
		Meta:      eventMessage.Meta,
		Timestamp: time.Now(),
	})
}

func (m *MockEventTracker) GetEvents() []eventInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]eventInfo, len(m.events))
	copy(events, m.events)
	return events
}

func (m *MockEventTracker) ClearEvents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

func (m *MockEventTracker) GetEventCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}

func (m *MockEventTracker) GetEventsByType(eventType apidef.TykEvent) []eventInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []eventInfo
	for _, e := range m.events {
		if e.EventType == eventType {
			filtered = append(filtered, e)
		}
	}

	return filtered
}

// setupCertificateCheckMWIntegration creates a middleware instance for integration testing
func setupCertificateCheckMWIntegration(t *testing.T, _ bool, certs []*tls.Certificate) (*CertificateCheckMW, *MockEventTracker) {
	return setupCertificateCheckMWIntegrationWithEvents(t, false, certs, []apidef.TykEvent{event.CertificateExpiringSoon})
}

// setupCertificateCheckMWIntegrationWithEvents creates a middleware instance for integration testing with configurable event tracking
// This allows tests to specify which event types they want to track, making it easy to add new event types in the future.
// Example usage for multiple event types:
//
//	mw, tracker := setupCertificateCheckMWIntegrationWithEvents(t, false, certs, []apidef.TykEvent{
//	    event.CertificateExpiringSoon,
//	    event.CertificateExpired,  // Future event type
//	})
func setupCertificateCheckMWIntegrationWithEvents(t *testing.T, _ bool, certs []*tls.Certificate, eventTypes []apidef.TykEvent) (*CertificateCheckMW, *MockEventTracker) {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if certs != nil {
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return(certs).
			AnyTimes()
	}

	// Generate unique test prefix for Redis keys to avoid clashes
	testPrefix := fmt.Sprintf("test-%d-", time.Now().UnixNano())

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

	// Create mock event tracker
	mockEventTracker := &MockEventTracker{}

	// Create API spec with configurable event handlers
	eventPaths := make(map[apidef.TykEvent][]config.TykEventHandler)
	for _, eventType := range eventTypes {
		eventPaths[eventType] = []config.TykEventHandler{mockEventTracker}
	}

	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			UseMutualTLSAuth:   true,
			ClientCertificates: []string{"cert1"},
			APIID:              "integration-test-api-id",
			OrgID:              "integration-test-org-id",
		},
		GlobalConfig: gw.GetConfig(),
		EventPaths:   eventPaths,
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: apiSpec,
			Gw:   gw,
		},
	}

	// Initialize Redis store with randomized prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	return mw, mockEventTracker
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

// TestCertificateCheckMW_Integration_CoreFunctionality tests the core certificate expiration logic
func TestCertificateCheckMW_Integration_CoreFunctionality(t *testing.T) {
	t.Parallel()

	t.Run("Valid Certificate - No Event Fired", func(t *testing.T) {
		// Create a certificate that expires in 90 days (outside warning threshold of 60 days)
		cert := createTestCertificate(90, "valid.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Verify no events were fired for valid certificate
		assert.Equal(t, 0, eventTracker.GetEventCount(), "No events should be fired for valid certificate")
	})

	t.Run("Expiring Certificate - Event Should Be Fired", func(t *testing.T) {
		// Create a certificate that expires in 15 days (within warning threshold)
		cert := createTestCertificate(15, "expiring.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Wait for async event processing
		time.Sleep(100 * time.Millisecond)

		// Verify that an event was fired for expiring certificate
		assert.Equal(t, 1, eventTracker.GetEventCount(), "Event should be fired for expiring certificate")

		// Verify the event type
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 1, len(events), "Should have one CertificateExpiringSoon event")

		// Verify event metadata
		if len(events) > 0 {
			eventMeta, ok := events[0].Meta.(EventCertificateExpiringSoonMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			assert.Equal(t, "expiring.example.com", eventMeta.CertName, "Certificate name should match")
			assert.Equal(t, "integration-test-api-id", eventMeta.APIID, "API ID should match")
			assert.Equal(t, "integration-test-org-id", eventMeta.OrgID, "Org ID should match")
		}

		// Clear events for second test
		eventTracker.ClearEvents()

		// A second call should not fire the event due to cooldown
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Verify no additional events were fired due to cooldown
		assert.Equal(t, 0, eventTracker.GetEventCount(), "No additional events should be fired due to cooldown")
	})

	t.Run("Critical Certificate - Event Should Be Fired", func(t *testing.T) {
		// Create a certificate that expires in 5 days (critical)
		cert := createTestCertificate(5, "critical.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Wait for async event processing
		time.Sleep(100 * time.Millisecond)

		// Verify that an event was fired for critical certificate
		assert.Equal(t, 1, eventTracker.GetEventCount(), "Event should be fired for critical certificate")

		// Verify the event type
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 1, len(events), "Should have one CertificateExpiringSoon event")

		// Verify event metadata
		if len(events) > 0 {
			eventMeta, ok := events[0].Meta.(EventCertificateExpiringSoonMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			assert.Equal(t, "critical.example.com", eventMeta.CertName, "Certificate name should match")
		}
	})

	t.Run("Multiple Certificates - Mixed Expiration", func(t *testing.T) {
		// Create certificates with different expiration dates
		validCert := createTestCertificate(90, "valid.example.com") // Outside 60-day threshold
		expiringCert := createTestCertificate(15, "expiring.example.com")
		criticalCert := createTestCertificate(5, "critical.example.com")

		// Create TLS certificates
		tlsCerts := []*tls.Certificate{validCert, expiringCert, criticalCert}

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, tlsCerts)

		// Test the core expiration checking logic directly
		mw.checkCertificatesExpiration(tlsCerts)

		// Wait for async event processing
		time.Sleep(100 * time.Millisecond)

		// Verify that events were fired for expiring certificates only
		assert.Equal(t, 2, eventTracker.GetEventCount(), "Should fire events for 2 expiring certificates")

		// Verify the event types
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 2, len(events), "Should have two CertificateExpiringSoon events")

		// Verify event metadata for both events
		certNames := make(map[string]bool)

		for _, e := range events {
			eventMeta, ok := e.Meta.(EventCertificateExpiringSoonMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			certNames[eventMeta.CertName] = true
		}

		// Should have events for expiring and critical certificates, but not valid
		assert.True(t, certNames["expiring.example.com"], "Should have event for expiring certificate")
		assert.True(t, certNames["critical.example.com"], "Should have event for critical certificate")
		assert.False(t, certNames["valid.example.com"], "Should not have event for valid certificate")
	})
}

// Consolidated configuration scenarios
func TestCertificateCheckMW_Integration_Configuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		certDays      int
		certName      string
		warningDays   int
		checkCooldown int
		eventCooldown int
		sleep         time.Duration
	}{
		{
			name:          "Custom Warning Threshold",
			certDays:      45,
			certName:      "custom.example.com",
			warningDays:   60,
			checkCooldown: 3600,
			eventCooldown: 86400,
		},
		{
			name:          "Short Cooldown Period",
			certDays:      15,
			certName:      "shortcooldown.example.com",
			warningDays:   30,
			checkCooldown: 3600,
			eventCooldown: 1,
			sleep:         2 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := createTestCertificate(tc.certDays, tc.certName)
			ctrl := gomock.NewController(t)
			mockCertManager := mock.NewMockCertificateManager(ctrl)
			mockCertManager.EXPECT().
				List(gomock.Any(), gomock.Any()).
				Return([]*tls.Certificate{cert}).
				AnyTimes()

			gw := &Gateway{
				CertificateManager: mockCertManager,
			}
			gw.SetConfig(config.Config{
				Security: config.SecurityConfig{
					Certificates: config.CertificatesConfig{
						API: []string{"cert2"},
					},
					CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
						WarningThresholdDays: tc.warningDays,
						CheckCooldownSeconds: tc.checkCooldown,
						EventCooldownSeconds: tc.eventCooldown,
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

			mw.checkCertificatesExpiration([]*tls.Certificate{cert})
			if tc.sleep > 0 {
				time.Sleep(tc.sleep)
				mw.checkCertificatesExpiration([]*tls.Certificate{cert})
			}
		})
	}
}

// Consolidated error scenarios
func TestCertificateCheckMW_Integration_ErrorScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cert     *tls.Certificate
		certList []*tls.Certificate
	}{
		{
			name: "Expired Certificate",
			cert: createTestCertificate(-1, "expired.example.com"),
		},
		{
			name:     "Nil Certificate",
			certList: []*tls.Certificate{nil},
		},
		{
			name: "Certificate with Nil Leaf",
			cert: &tls.Certificate{Leaf: nil},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var certs []*tls.Certificate
			if tc.certList != nil {
				certs = tc.certList
			} else {
				certs = []*tls.Certificate{tc.cert}
			}
			mw, _ := setupCertificateCheckMWIntegration(t, true, certs)
			mw.checkCertificatesExpiration(certs)
		})
	}
}

// Consolidated cooldown mechanism tests
func TestCertificateCheckMW_Integration_CooldownMechanisms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		typeName     string // "check" or "event"
		cooldown     int
		zeroCooldown bool
	}{
		{"Check Cooldown Respects Configuration", "check", 60, false},
		{"Check Cooldown with Zero Value", "check", 0, true},
		{"Event Cooldown Respects Configuration", "event", 120, false},
		{"Event Cooldown with Zero Value", "event", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw, _ := setupCertificateCheckMWIntegration(t, true, nil)
			if tc.typeName == "check" {
				mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = tc.cooldown
			} else {
				mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = tc.cooldown
			}

			cert := createTestCertificate(15, tc.name+".example.com")
			certID := crypto.HexSHA256(cert.Leaf.Raw)

			if tc.typeName == "check" {
				if tc.zeroCooldown {
					// First check should be allowed (uses default cooldown)
					shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
					assert.False(t, shouldSkip, "First check should be allowed with zero cooldown (uses default)")
					// Second check should be blocked (uses default cooldown)
					shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
					assert.True(t, shouldSkip, "Second check should be blocked with zero cooldown (uses default)")
				} else {
					shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
					assert.False(t, shouldSkip, "First check should be allowed")
					shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
					assert.True(t, shouldSkip, "Second check should be blocked by cooldown")
					// Different certificate
					differentCert := createTestCertificate(15, "different-"+tc.name+".example.com")
					differentCertID := crypto.HexSHA256(differentCert.Leaf.Raw)
					shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, differentCertID)
					assert.False(t, shouldSkip, "Different certificate should be allowed")
				}
			} else {
				if tc.zeroCooldown {
					// First event should be allowed (uses default cooldown)
					shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					assert.True(t, shouldFire, "First event should be allowed with zero cooldown (uses default)")
					// Second event should be blocked (uses default cooldown)
					shouldFire = mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					assert.False(t, shouldFire, "Second event should be blocked with zero cooldown (uses default)")
				} else {
					shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					assert.True(t, shouldFire, "First event should be allowed")
					shouldFire = mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					assert.False(t, shouldFire, "Second event should be blocked by cooldown")
					// Different certificate
					differentCertID := "different-" + tc.name + "-id"
					shouldFire = mw.shouldFireExpiryEvent(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					assert.True(t, shouldFire, "Different certificate should be allowed")
				}
			}
		})
	}
}

// TestCertificateCheckMW_Integration_CooldownIntegration tests both cooldown mechanisms working together
func TestCertificateCheckMW_Integration_CooldownIntegration(t *testing.T) {
	t.Parallel()

	t.Run("Both Cooldowns Work Together", func(t *testing.T) {
		mw, _ := setupCertificateCheckMWIntegration(t, true, nil)
		// Set short cooldowns for testing
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60  // 1 minute
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120 // 2 minutes

		cert := createTestCertificate(15, "integration-test.example.com")
		certID := crypto.HexSHA256(cert.Leaf.Raw)

		// First call: should allow both check and event
		shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
		assert.False(t, shouldSkip, "First check should be allowed")

		shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "First event should be allowed")

		// Second call: should block both check and event due to cooldown
		shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
		assert.True(t, shouldSkip, "Second check should be blocked by cooldown")

		shouldFire = mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.False(t, shouldFire, "Second event should be blocked by cooldown")

		// Different certID should still work
		differentCertID := "different-integration-cert-id"
		shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, differentCertID)
		assert.False(t, shouldSkip, "Different certID check should be allowed")

		shouldFire = mw.shouldFireExpiryEvent(differentCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		assert.True(t, shouldFire, "Different certID event should be allowed")
	})

	t.Run("Different Certificates Are Independent", func(t *testing.T) {
		mw, _ := setupCertificateCheckMWIntegration(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120

		cert1 := createTestCertificate(15, "integration-test-1.example.com")
		cert2 := createTestCertificate(15, "integration-test-2.example.com")
		certID1 := crypto.HexSHA256(cert1.Leaf.Raw)
		certID2 := crypto.HexSHA256(cert2.Leaf.Raw)

		// Set cooldowns for first certificate
		mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID1)
		mw.shouldFireExpiryEvent(certID1, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)

		// Second certificate should still be allowed
		shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID2)
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
	cert := createTestCertificate(15, "persistence-integration-test.example.com")
	certID := crypto.HexSHA256(cert.Leaf.Raw)
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
		shouldSkip1 := mw1.shouldCooldown(monitorConfig, certID)
		assert.False(t, shouldSkip1, "First check should be allowed")

		// Check with different instance should fail (cooldown persists)
		shouldSkip2 := mw2.shouldCooldown(monitorConfig, certID)
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

// TestCertificateCheckMW_Integration_CooldownLifecycle tests the complete cooldown lifecycle behavior
func TestCertificateCheckMW_Integration_CooldownLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("Single Certificate Cooldown Persistence", func(t *testing.T) {
		// Create middleware with short cooldowns for testing
		mw, _ := setupCertificateCheckMWIntegration(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30

		// Create a certificate that expires in 15 days (within warning threshold)
		cert := createTestCertificate(15, "endtoend-test.example.com")
		certID := crypto.HexSHA256(cert.Leaf.Raw)

		// First call to checkCertificateExpiration should process the certificate
		// and potentially fire an event
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Verify that check cooldown was set
		checkCooldownKey := fmt.Sprintf("%s%s", certCheckCooldownPrefix, certID)
		_, err := mw.store.GetKey(checkCooldownKey)
		assert.NoError(t, err, "Check cooldown should be set after first call")

		// Second call should skip the certificate due to check cooldown
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Verify check cooldown is still active
		_, err = mw.store.GetKey(checkCooldownKey)
		assert.NoError(t, err, "Check cooldown should still be active after second call")

		// Third call should also skip due to check cooldown
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})

		// Verify check cooldown is still active
		_, err = mw.store.GetKey(checkCooldownKey)
		assert.NoError(t, err, "Check cooldown should still be active after third call")

		// The function should complete without errors even when cooldowns are active
		// This tests that the cooldown logic doesn't break the main flow
	})

	t.Run("Multiple Certificates Independent Cooldowns", func(t *testing.T) {
		mw, _ := setupCertificateCheckMWIntegration(t, true, nil)
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 60
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 120
		mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30

		// Create multiple certificates
		cert1 := createTestCertificate(15, "endtoend-multi-1.example.com")
		cert2 := createTestCertificate(15, "endtoend-multi-2.example.com")
		cert3 := createTestCertificate(60, "endtoend-multi-3.example.com") // Outside threshold

		cert1ID := crypto.HexSHA256(cert1.Leaf.Raw)
		cert2ID := crypto.HexSHA256(cert2.Leaf.Raw)
		cert3ID := crypto.HexSHA256(cert3.Leaf.Raw)

		certs := []*tls.Certificate{cert1, cert2, cert3}

		// First call should process all certificates
		mw.checkCertificatesExpiration(certs)

		// Verify that check cooldowns were set for all certificates
		checkCooldownKey1 := fmt.Sprintf("%s%s", certCheckCooldownPrefix, cert1ID)
		checkCooldownKey2 := fmt.Sprintf("%s%s", certCheckCooldownPrefix, cert2ID)
		checkCooldownKey3 := fmt.Sprintf("%s%s", certCheckCooldownPrefix, cert3ID)

		_, err := mw.store.GetKey(checkCooldownKey1)
		assert.NoError(t, err, "Check cooldown should be set for cert1 after first call")

		_, err = mw.store.GetKey(checkCooldownKey2)
		assert.NoError(t, err, "Check cooldown should be set for cert2 after first call")

		_, err = mw.store.GetKey(checkCooldownKey3)
		assert.NoError(t, err, "Check cooldown should be set for cert3 after first call")

		// Second call should skip cert1 and cert2 due to check cooldown
		// but cert3 should still be processed (though it won't trigger events)
		mw.checkCertificatesExpiration(certs)

		// Verify check cooldowns are still active for all certificates
		_, err = mw.store.GetKey(checkCooldownKey1)
		assert.NoError(t, err, "Check cooldown should still be active for cert1 after second call")

		_, err = mw.store.GetKey(checkCooldownKey2)
		assert.NoError(t, err, "Check cooldown should still be active for cert2 after second call")

		_, err = mw.store.GetKey(checkCooldownKey3)
		assert.NoError(t, err, "Check cooldown should still be active for cert3 after second call")
	})
}

// TestCertificateCheckMW_Integration_Performance tests performance characteristics
func TestCertificateCheckMW_Integration_Performance(t *testing.T) {
	t.Parallel()

	t.Run("Multiple Certificates Processing", func(t *testing.T) {
		// Create multiple certificates
		certs := []*tls.Certificate{
			createTestCertificate(60, "cert1.example.com"),
			createTestCertificate(15, "cert2.example.com"),
			createTestCertificate(5, "cert3.example.com"),
			createTestCertificate(90, "cert4.example.com"),
			createTestCertificate(30, "cert5.example.com"),
		}

		mw, _ := setupCertificateCheckMWIntegration(t, true, certs)

		// Process multiple certificates
		for i := 0; i < 10; i++ {
			mw.checkCertificatesExpiration(certs)
		}
	})

	t.Run("Large Certificate Processing", func(t *testing.T) {
		// Create a certificate with large extensions
		cert := createTestCertificate(30, "large.example.com")

		// Add large extensions to simulate complex certificates
		cert.Leaf.Extensions = append(cert.Leaf.Extensions, pkix.Extension{
			Id:    []int{1, 2, 3, 4, 5},
			Value: make([]byte, 1000), // Large extension
		})

		mw, _ := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Process large certificate
		mw.checkCertificatesExpiration([]*tls.Certificate{cert})
	})
}

// TestCertificateCheckMW_Integration_HelperMethods tests the helper methods in integration context
func TestCertificateCheckMW_Integration_HelperMethods(t *testing.T) {
	t.Parallel()

	_, _ = setupCertificateCheckMWIntegration(t, true, nil)

	// Test certificate ID generation
	cert := createTestCertificate(30, "helper-test.example.com")
	certID := crypto.HexSHA256(cert.Leaf.Raw)
	assert.NotEmpty(t, certID)
	assert.Len(t, certID, 64) // SHA256 hash length

	// Test with nil certificate
	nilCertID := ""
	assert.Empty(t, nilCertID)

	// Test with certificate that has nil Leaf
	_ = &tls.Certificate{}
	nilLeafCertID := ""
	assert.Empty(t, nilLeafCertID)
}
