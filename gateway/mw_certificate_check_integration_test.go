package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/storage"
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
	return setupCertificateCheckMWIntegrationWithEvents(t, false, certs, []apidef.TykEvent{event.CertificateExpiringSoon, event.CertificateExpired})
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

	logger, _ := logrustest.NewNullLogger()

	var err error
	mw.expiryCheckBatcher, err = certcheck.NewCertificateExpiryCheckBatcher(
		logrus.NewEntry(logger),
		certcheck.APIMetaData{
			APIID:   mw.Spec.APIID,
			APIName: mw.Spec.Name,
		},
		mw.Gw.GetConfig().Security.CertificateExpiryMonitor,
		mw.store,
		mw.Spec.FireEvent)
	require.NoError(t, err)

	mw.expiryCheckBatcher.SetFlushInterval(10 * time.Millisecond)

	return mw, mockEventTracker
}

// TestCertificateCheckMW_Integration_CoreFunctionality tests the core certificate expiration logic
func TestCertificateCheckMW_Integration_CoreFunctionality(t *testing.T) {
	t.Run("Valid Certificate - No Event Fired", func(t *testing.T) {
		t.Cleanup(certcheck.GetCooldownLRUCache().Purge)

		// Create a certificate that expires in 90 days (outside warning threshold of 60 days)
		cert := createTestCertificate(90, "valid.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Verify no events were fired for valid certificate
		assert.Equal(t, 0, eventTracker.GetEventCount(), "No events should be fired for valid certificate")
	})

	t.Run("Expiring Certificate - Event Should Be Fired", func(t *testing.T) {
		t.Cleanup(certcheck.GetCooldownLRUCache().Purge)

		// Create a certificate that expires in 15 days (within warning threshold)
		cert := createTestCertificate(15, "expiring.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Setup and start the background batcher
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(20)*time.Millisecond)
		mw.expiryCheckBatcher.RunInBackground(ctx)

		// Wait for async event processing and cancel context afterwards
		time.Sleep(15 * time.Millisecond)
		cancelFunc()

		// Verify that an event was fired for expiring certificate
		assert.Equal(t, 1, eventTracker.GetEventCount(), "Event should be fired for expiring certificate")

		// Verify the event type
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 1, len(events), "Should have one CertificateExpiringSoon event")

		// Verify event metadata
		if len(events) > 0 {
			eventMeta, ok := events[0].Meta.(certcheck.EventCertificateExpiringSoonMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			assert.Equal(t, "expiring.example.com", eventMeta.CertName, "Certificate name should match")
		}

		// Clear events for second test
		eventTracker.ClearEvents()

		// A second call should not fire the event due to cooldown
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Verify no additional events were fired due to cooldown
		assert.Equal(t, 0, eventTracker.GetEventCount(), "No additional events should be fired due to cooldown")
	})

	t.Run("Critical Certificate - Event Should Be Fired", func(t *testing.T) {
		t.Cleanup(certcheck.GetCooldownLRUCache().Purge)

		// Create a certificate that expires in 5 days (critical)
		cert := createTestCertificate(5, "critical.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Setup and start the background batcher
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(20)*time.Millisecond)
		mw.expiryCheckBatcher.RunInBackground(ctx)

		// Wait for async event processing and cancel context afterwards
		time.Sleep(15 * time.Millisecond)
		cancelFunc()

		// Verify that an event was fired for critical certificate
		assert.Equal(t, 1, eventTracker.GetEventCount(), "Event should be fired for critical certificate")

		// Verify the event type
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 1, len(events), "Should have one CertificateExpiringSoon event")

		// Verify event metadata
		if len(events) > 0 {
			eventMeta, ok := events[0].Meta.(certcheck.EventCertificateExpiringSoonMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			assert.Equal(t, "critical.example.com", eventMeta.CertName, "Certificate name should match")
		}
	})

	t.Run("Expired Certificate - Event Should Be Fired", func(t *testing.T) {
		t.Cleanup(certcheck.GetCooldownLRUCache().Purge)

		// Create a certificate that expires in 5 days (critical)
		cert := createTestCertificate(-15, "expired.example.com")

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, []*tls.Certificate{cert})

		// Test the core expiration checking logic directly
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Setup and start the background batcher
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(20)*time.Millisecond)
		mw.expiryCheckBatcher.RunInBackground(ctx)

		// Wait for async event processing and cancel context afterwards
		time.Sleep(15 * time.Millisecond)
		cancelFunc()

		// Verify that an event was fired for expired certificate
		assert.Equal(t, 1, eventTracker.GetEventCount(), "Event should be fired for critical certificate")

		// Verify the event type
		events := eventTracker.GetEventsByType(event.CertificateExpired)
		assert.Equal(t, 1, len(events), "Should have one CertificateExpired event")

		// Verify event metadata
		if len(events) > 0 {
			eventMeta, ok := events[0].Meta.(certcheck.EventCertificateExpiredMeta)
			assert.True(t, ok, "Event metadata should be EventCertificateExpiringSoonMeta")
			assert.Equal(t, "expired.example.com", eventMeta.CertName, "Certificate name should match")
		}

		// Clear events for second test
		eventTracker.ClearEvents()

		// A second call should not fire the event due to cooldown
		mw.batchCertificatesExpirationCheck([]*tls.Certificate{cert})

		// Verify no additional events were fired due to cooldown
		assert.Equal(t, 0, eventTracker.GetEventCount(), "No additional events should be fired due to cooldown")
	})

	t.Run("Multiple Certificates - Mixed Expiration", func(t *testing.T) {
		t.Cleanup(certcheck.GetCooldownLRUCache().Purge)

		// Create certificates with different expiration dates
		validCert := createTestCertificate(90, "valid.example.com") // Outside 60-day threshold
		expiringCert := createTestCertificate(15, "expiring.example.com")
		criticalCert := createTestCertificate(5, "critical.example.com")
		expiredCert := createTestCertificate(-15, "expired.example.com")

		// Create TLS certificates
		tlsCerts := []*tls.Certificate{validCert, expiringCert, criticalCert, expiredCert}

		mw, eventTracker := setupCertificateCheckMWIntegration(t, true, tlsCerts)

		// Test the core expiration checking logic directly
		mw.batchCertificatesExpirationCheck(tlsCerts)

		// Setup and start the background batcher
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(20)*time.Millisecond)
		mw.expiryCheckBatcher.RunInBackground(ctx)

		// Wait for async event processing and cancel context afterwards
		time.Sleep(15 * time.Millisecond)
		cancelFunc()

		// Verify that events were fired for expiring certificates only
		assert.Equal(t, 3, eventTracker.GetEventCount(), "Should fire events for 3 expiring or expired certificates")

		// Verify the event types
		events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
		assert.Equal(t, 2, len(events), "Should have two CertificateExpiringSoon events")

		// Verify event metadata for both events
		certNames := make(map[string]bool)

		for _, e := range events {
			eventMeta, ok := e.Meta.(certcheck.EventCertificateExpiringSoonMeta)
			if ok {
				certNames[eventMeta.CertName] = true
			} else {
				certNames[eventMeta.CertName] = false
			}
		}

		// Should have events for expiring and critical certificates, but not valid
		assert.True(t, certNames["expiring.example.com"], "Should have event for expiring certificate")
		assert.True(t, certNames["critical.example.com"], "Should have event for critical certificate")
		assert.False(t, certNames["expired.example.com"], "Should not have event for expired certificate")
		assert.False(t, certNames["valid.example.com"], "Should not have event for valid certificate")

		// Verify the event types
		events = eventTracker.GetEventsByType(event.CertificateExpired)
		assert.Equal(t, 1, len(events), "Should have two CertificateExpiringSoon events")

		// Verify event metadata for both events
		certNames = make(map[string]bool)

		for _, e := range events {
			eventMeta, ok := e.Meta.(certcheck.EventCertificateExpiredMeta)
			if ok {
				certNames[eventMeta.CertName] = true
			} else {
				certNames[eventMeta.CertName] = false
			}
		}

		// Should have events for expiring and critical certificates, but not valid
		assert.False(t, certNames["expiring.example.com"], "Should not have event for expiring certificate")
		assert.False(t, certNames["critical.example.com"], "Should not have event for critical certificate")
		assert.True(t, certNames["expired.example.com"], "Should have event for expired certificate")
		assert.False(t, certNames["valid.example.com"], "Should not have event for valid certificate")
	})
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
			ctx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(20)*time.Millisecond)
			mw.expiryCheckBatcher.RunInBackground(ctx)
			mw.batchCertificatesExpirationCheck(certs)
			cancelFunc()
		})
	}
}
