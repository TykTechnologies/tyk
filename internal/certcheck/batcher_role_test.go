package certcheck

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"

	storagemock "github.com/TykTechnologies/tyk/storage/mock"
)

// TestNewCertificateExpiryCheckBatcherWithRole_RoleParameter tests that the role is properly set
func TestNewCertificateExpiryCheckBatcherWithRole_RoleParameter(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		expectedRole string
	}{
		{
			name:         "client role",
			role:         "client",
			expectedRole: "client",
		},
		{
			name:         "upstream role",
			role:         "upstream",
			expectedRole: "upstream",
		},
		{
			name:         "server role",
			role:         "server",
			expectedRole: "server",
		},
		{
			name:         "ca role",
			role:         "ca",
			expectedRole: "ca",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			logger, _ := logrustest.NewNullLogger()
			redisStorageMock := storagemock.NewMockHandler(ctrl)

			batcher, err := NewCertificateExpiryCheckBatcherWithRole(
				logrus.NewEntry(logger),
				testApiMetaData,
				config.CertificateExpiryMonitorConfig{},
				redisStorageMock,
				nil,
				tt.role,
			)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedRole, batcher.certificateRole)
		})
	}
}

// TestNewCertificateExpiryCheckBatcher_DefaultsToClientRole tests backward compatibility
func TestNewCertificateExpiryCheckBatcher_DefaultsToClientRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger, _ := logrustest.NewNullLogger()
	redisStorageMock := storagemock.NewMockHandler(ctrl)

	batcher, err := NewCertificateExpiryCheckBatcher(
		logrus.NewEntry(logger),
		testApiMetaData,
		config.CertificateExpiryMonitorConfig{},
		redisStorageMock,
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, "client", batcher.certificateRole, "Default constructor should set role to 'client' for backward compatibility")
}

// TestCertificateExpiryCheckBatcher_RoleInExpiredEvent tests that expired events include cert_role
func TestCertificateExpiryCheckBatcher_RoleInExpiredEvent(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		expectedRole string
	}{
		{
			name:         "client certificate expired event",
			role:         "client",
			expectedRole: "client",
		},
		{
			name:         "upstream certificate expired event",
			role:         "upstream",
			expectedRole: "upstream",
		},
		{
			name:         "server certificate expired event",
			role:         "server",
			expectedRole: "server",
		},
		{
			name:         "ca certificate expired event",
			role:         "ca",
			expectedRole: "ca",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualFiredEvent event.Event
			var actualEventMeta EventCertificateExpiredMeta
			fireEvent := func(event event.Event, meta any) {
				actualFiredEvent = event
				actualEventMeta = meta.(EventCertificateExpiredMeta)
			}

			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 120,
			}

			batcher, err := NewCertificateExpiryCheckBatcherWithRole(
				batcherMocks.logger,
				testApiMetaData,
				expiryCheckConfig,
				batcherMocks.redisStorageMock,
				fireEvent,
				tt.role,
			)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			// Add expired certificate
			now := time.Now()
			expiredSince := now.Add(-50 * time.Hour)
			err = batcher.Add(CertInfo{
				ID:          "test-cert-id",
				UntilExpiry: -50 * time.Hour,
				NotAfter:    expiredSince,
				CommonName:  "test-cert",
			})
			require.NoError(t, err)

			// Setup mocks
			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").Return(true, nil)
			batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").Return(false, nil)
			batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").Return(true, nil)
			batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").Return(false, nil)
			batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(nil)
			batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(nil)
			batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(nil)
			batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(nil)

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			// Wait for event to fire
			time.Sleep(50 * time.Millisecond)
			cancel()

			// Verify event
			assert.Equal(t, event.CertificateExpired, actualFiredEvent)
			assert.Equal(t, tt.expectedRole, actualEventMeta.CertRole, "Event metadata should include correct cert_role")
			assert.Equal(t, "test-cert-id", actualEventMeta.CertID)
			assert.Equal(t, "test-cert", actualEventMeta.CertName)
			assert.Equal(t, "123abc", actualEventMeta.APIID)
		})
	}
}

// TestCertificateExpiryCheckBatcher_RoleInExpiringSoonEvent tests that expiring soon events include cert_role
func TestCertificateExpiryCheckBatcher_RoleInExpiringSoonEvent(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		expectedRole string
	}{
		{
			name:         "client certificate expiring soon event",
			role:         "client",
			expectedRole: "client",
		},
		{
			name:         "upstream certificate expiring soon event",
			role:         "upstream",
			expectedRole: "upstream",
		},
		{
			name:         "server certificate expiring soon event",
			role:         "server",
			expectedRole: "server",
		},
		{
			name:         "ca certificate expiring soon event",
			role:         "ca",
			expectedRole: "ca",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualFiredEvent event.Event
			var actualEventMeta EventCertificateExpiringSoonMeta
			fireEvent := func(event event.Event, meta any) {
				actualFiredEvent = event
				actualEventMeta = meta.(EventCertificateExpiringSoonMeta)
			}

			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 120,
			}

			batcher, err := NewCertificateExpiryCheckBatcherWithRole(
				batcherMocks.logger,
				testApiMetaData,
				expiryCheckConfig,
				batcherMocks.redisStorageMock,
				fireEvent,
				tt.role,
			)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			// Add expiring soon certificate
			now := time.Now()
			expiry := now.Add(48 * time.Hour)
			err = batcher.Add(CertInfo{
				ID:          "test-cert-id",
				UntilExpiry: 48 * time.Hour,
				NotAfter:    expiry,
				CommonName:  "test-cert",
			})
			require.NoError(t, err)

			// Setup mocks
			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").Return(true, nil)
			batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").Return(false, nil)
			batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").Return(true, nil)
			batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").Return(false, nil)
			batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(nil)
			batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(nil)
			batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(nil)
			batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(nil)

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			// Wait for event to fire
			time.Sleep(50 * time.Millisecond)
			cancel()

			// Verify event
			assert.Equal(t, event.CertificateExpiringSoon, actualFiredEvent)
			assert.Equal(t, tt.expectedRole, actualEventMeta.CertRole, "Event metadata should include correct cert_role")
			assert.Equal(t, "test-cert-id", actualEventMeta.CertID)
			assert.Equal(t, "test-cert", actualEventMeta.CertName)
			assert.Equal(t, "123abc", actualEventMeta.APIID)
			assert.Equal(t, 2, actualEventMeta.DaysRemaining)
		})
	}
}

// TestCertificateExpiryCheckBatcher_RolePreservedThroughCooldowns tests that role is maintained through cooldown checks
func TestCertificateExpiryCheckBatcher_RolePreservedThroughCooldowns(t *testing.T) {
	var eventCount int
	var lastEventMeta EventCertificateExpiringSoonMeta
	fireEvent := func(event event.Event, meta any) {
		eventCount++
		lastEventMeta = meta.(EventCertificateExpiringSoonMeta)
	}

	ctrl, batcherMocks := createBatcherMocks(t)
	t.Cleanup(ctrl.Finish)

	expiryCheckConfig := config.CertificateExpiryMonitorConfig{
		WarningThresholdDays: 30,
		CheckCooldownSeconds: 1,  // Very short cooldown
		EventCooldownSeconds: 60, // Longer event cooldown
	}

	batcher, err := NewCertificateExpiryCheckBatcherWithRole(
		batcherMocks.logger,
		testApiMetaData,
		expiryCheckConfig,
		batcherMocks.redisStorageMock,
		fireEvent,
		"upstream", // Test with upstream role
	)
	require.NoError(t, err)

	batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
	batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
	batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

	now := time.Now()
	expiry := now.Add(48 * time.Hour)
	err = batcher.Add(CertInfo{
		ID:          "test-cert-id",
		UntilExpiry: 48 * time.Hour,
		NotAfter:    expiry,
		CommonName:  "upstream-test-cert",
	})
	require.NoError(t, err)

	// First check - should fire event
	batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").Return(false, nil)
	batcherMocks.fallbackCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").Return(false, nil)
	batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").Return(false, nil)
	batcherMocks.fallbackCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").Return(false, nil)
	batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(1)).Return(nil)
	batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(1)).Return(nil)
	batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(60)).Return(nil)
	batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(60)).Return(nil)

	// Second check after cooldown - should skip due to event cooldown
	batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").Return(true, nil).AnyTimes()
	batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").Return(true, nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	go batcher.RunInBackground(ctx)

	// Wait for events
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Verify only one event fired (due to event cooldown)
	assert.Equal(t, 1, eventCount, "Only one event should fire due to event cooldown")
	assert.Equal(t, "upstream", lastEventMeta.CertRole, "Role should be preserved as 'upstream'")
	assert.Equal(t, "upstream-test-cert", lastEventMeta.CertName)
}

// TestCertificateExpiryCheckBatcher_RoleWithCacheErrors tests that role is maintained even when cache operations fail
func TestCertificateExpiryCheckBatcher_RoleWithCacheErrors(t *testing.T) {
	var actualEventMeta EventCertificateExpiredMeta
	fireEvent := func(event event.Event, meta any) {
		actualEventMeta = meta.(EventCertificateExpiredMeta)
	}

	ctrl, batcherMocks := createBatcherMocks(t)
	t.Cleanup(ctrl.Finish)

	expiryCheckConfig := config.CertificateExpiryMonitorConfig{
		WarningThresholdDays: 30,
		CheckCooldownSeconds: 60,
		EventCooldownSeconds: 120,
	}

	batcher, err := NewCertificateExpiryCheckBatcherWithRole(
		batcherMocks.logger,
		testApiMetaData,
		expiryCheckConfig,
		batcherMocks.redisStorageMock,
		fireEvent,
		"upstream",
	)
	require.NoError(t, err)

	batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
	batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
	batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

	now := time.Now()
	expiredSince := now.Add(-50 * time.Hour)
	err = batcher.Add(CertInfo{
		ID:          "test-cert-id",
		UntilExpiry: -50 * time.Hour,
		NotAfter:    expiredSince,
		CommonName:  "test-cert",
	})
	require.NoError(t, err)

	// Simulate cache failures
	batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").Return(false, errors.New("cache error"))
	batcherMocks.fallbackCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").Return(false, nil)
	batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").Return(false, errors.New("cache error"))
	batcherMocks.fallbackCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").Return(false, nil)
	batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(errors.New("set failed"))
	batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).Return(errors.New("set failed"))
	batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(errors.New("set failed"))
	batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).Return(errors.New("set failed"))

	ctx, cancel := context.WithCancel(context.Background())
	go batcher.RunInBackground(ctx)

	time.Sleep(50 * time.Millisecond)
	cancel()

	// Verify event still fires with correct role despite cache errors
	assert.Equal(t, "upstream", actualEventMeta.CertRole, "Role should be 'upstream' even with cache errors")
	assert.Equal(t, "test-cert-id", actualEventMeta.CertID)
}
