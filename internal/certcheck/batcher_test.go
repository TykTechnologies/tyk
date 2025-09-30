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
	"github.com/TykTechnologies/tyk/internal/model"

	storagemock "github.com/TykTechnologies/tyk/storage/mock"
)

var testApiMetaData = APIMetaData{
	APIID:   "123abc",
	APIName: "API",
}

type BatcherMocks struct {
	ctrl              *gomock.Controller
	logger            *logrus.Entry
	redisStorageMock  *storagemock.MockHandler
	localCacheMock    *MockCooldownCache
	fallbackCacheMock *MockCooldownCache
}

func TestBatch(t *testing.T) {
	batch := NewBatch()
	assert.Equal(t, 0, batch.Size())

	firstCert := CertInfo{ID: "first"}
	secondCert := CertInfo{ID: "second"}

	batch.Append(firstCert)
	batch.Append(secondCert)
	batch.Append(firstCert)
	assert.Equal(t, 2, batch.Size())

	copiedBatch := batch.CopyAndClear()
	assert.Equal(t, 2, len(copiedBatch))
	assert.Equal(t, firstCert.ID, copiedBatch[0].ID)
	assert.Equal(t, secondCert.ID, copiedBatch[1].ID)
	assert.Equal(t, 0, batch.Size())

}

func TestNewCertificateExpiryCheckBatcher_Add(t *testing.T) {
	ctrl, batcherMocks := createBatcherMocks(t)
	t.Cleanup(ctrl.Finish)

	batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, config.CertificateExpiryMonitorConfig{}, batcherMocks.redisStorageMock, nil)
	require.NoError(t, err)
	require.Equal(t, 0, batcher.batch.Size())

	err = batcher.Add(CertInfo{ID: "first"})
	assert.NoError(t, err)
	assert.Equal(t, 1, batcher.batch.Size())
}

func TestCertificateExpiryCheckBatcher(t *testing.T) {
	t.Run("With check cooldown", func(t *testing.T) {
		t.Run("Should skip event firing checks when the check cooldown is active in local cache", func(t *testing.T) {
			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 60,
			}

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			err = batcher.Add(CertInfo{ID: "test-cert-id"})
			require.NoError(t, err)

			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
				Return(true, nil)

			batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
				Return(true, nil)

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			cancel()
			require.Eventuallyf(t, func() bool {
				<-ctx.Done()
				return true
			}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
		})

		t.Run("Should fallback if local cache check fails on initial key check", func(t *testing.T) {
			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 60,
			}

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			err = batcher.Add(CertInfo{ID: "test-cert-id"})
			require.NoError(t, err)

			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
				Return(false, errors.New("test error"))

			batcherMocks.fallbackCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
				Return(true, nil)

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			cancel()
			require.Eventuallyf(t, func() bool {
				<-ctx.Done()
				return true
			}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
		})

		t.Run("Should fallback if local cache check fails on actual value check", func(t *testing.T) {
			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 60,
			}

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			err = batcher.Add(CertInfo{ID: "test-cert-id"})
			require.NoError(t, err)

			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
				Return(true, nil)

			batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
				Return(false, errors.New("local cache error"))

			batcherMocks.fallbackCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
				Return(true, nil)

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			cancel()
			require.Eventuallyf(t, func() bool {
				<-ctx.Done()
				return true
			}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
		})

		t.Run("Should skip certificate if fallback fails too", func(t *testing.T) {
			ctrl, batcherMocks := createBatcherMocks(t)
			t.Cleanup(ctrl.Finish)

			expiryCheckConfig := config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 60,
				EventCooldownSeconds: 60,
			}

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
			require.NoError(t, err)

			batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
			batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
			batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

			err = batcher.Add(CertInfo{ID: "test-cert-id"})
			require.NoError(t, err)

			batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
				Return(false, nil)

			batcherMocks.fallbackCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
				Return(false, errors.New("fallback cache error"))

			ctx, cancel := context.WithCancel(context.Background())
			go batcher.RunInBackground(ctx)

			cancel()
			require.Eventuallyf(t, func() bool {
				<-ctx.Done()
				return true
			}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
		})
	})

	t.Run("With fire event cooldown", func(t *testing.T) {
		t.Run("And cooldown is active", func(t *testing.T) {
			t.Run("Should skip event firing but check for its cooldown in local cache", func(t *testing.T) {
				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 30,
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				err = batcher.Add(CertInfo{ID: "test-cert-id"})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
			})

			t.Run("Should skip event firing but check for its cooldown in fallback cache when initial lookup in local cache fails", func(t *testing.T) {
				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 30,
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				err = batcher.Add(CertInfo{ID: "test-cert-id"})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(false, errors.New("local cache error"))

				batcherMocks.fallbackCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
			})

			t.Run("Should skip event firing but check for its cooldown in fallback cache when value retrieval in local cache fails", func(t *testing.T) {
				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 30,
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				err = batcher.Add(CertInfo{ID: "test-cert-id"})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, errors.New("local cache error"))

				batcherMocks.fallbackCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
			})

			t.Run("Should skip event firing when local cache and fallback cache fail", func(t *testing.T) {
				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 30,
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				err = batcher.Add(CertInfo{ID: "test-cert-id"})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, errors.New("local cache error"))

				batcherMocks.fallbackCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, errors.New("fallback cache error"))

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
			})
		})

		t.Run("And cooldown is inactive", func(t *testing.T) {
			t.Run("Should not fire event when certificate is not expired or soon to expire", func(t *testing.T) {
				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: 1,
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:               "test-cert-id",
					HoursUntilExpiry: 48,
					NotAfter:         expiry,
					CommonName:       "test-cert",
				})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")
			})

			t.Run("Should fire event when certificate is expired", func(t *testing.T) {
				var actualFiredEvent event.Event
				var actualEventMeta EventCertificateExpiredMeta
				fireEvent := func(event event.Event, meta any) {
					actualFiredEvent = event
					actualEventMeta = meta.(EventCertificateExpiredMeta)
				}

				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					// Let's not provide WarningThresholdDays to test the default fallback
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiredSince := now.Add(-50 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:               "test-cert-id",
					HoursUntilExpiry: -50,
					NotAfter:         expiredSince,
					CommonName:       "test-cert",
				})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")

				assert.Equal(t, event.CertificateExpired, actualFiredEvent)
				assert.Equal(t, EventCertificateExpiredMeta{
					EventMetaDefault: model.EventMetaDefault{
						Message: "Certificate test-cert is expired since 2 days and 2 hours",
					},
					CertID:          "test-cert-id",
					CertName:        "test-cert",
					ExpiredAt:       expiredSince,
					DaysSinceExpiry: 2,
					APIID:           "123abc",
				}, actualEventMeta)
			})

			t.Run("Should fire event when certificate is soon to expire", func(t *testing.T) {
				var actualFiredEvent event.Event
				var actualEventMeta EventCertificateExpiringSoonMeta
				fireEvent := func(event event.Event, meta any) {
					actualFiredEvent = event
					actualEventMeta = meta.(EventCertificateExpiringSoonMeta)
				}

				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					// Let's not provide WarningThresholdDays to test the default fallback
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:               "test-cert-id",
					HoursUntilExpiry: 48,
					NotAfter:         expiry,
					CommonName:       "test-cert",
				})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(nil)

				batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(nil)

				batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(nil)

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")

				assert.Equal(t, event.CertificateExpiringSoon, actualFiredEvent)
				assert.Equal(t, EventCertificateExpiringSoonMeta{
					EventMetaDefault: model.EventMetaDefault{
						Message: "Certificate test-cert is expiring in 2 days",
					},
					CertID:        "test-cert-id",
					CertName:      "test-cert",
					ExpiresAt:     expiry,
					DaysRemaining: 2,
					APIID:         "123abc",
				}, actualEventMeta)
			})

			t.Run("Should not brak when setting cooldowns fail", func(t *testing.T) {
				var actualFiredEvent event.Event
				var actualEventMeta EventCertificateExpiringSoonMeta
				fireEvent := func(event event.Event, meta any) {
					actualFiredEvent = event
					actualEventMeta = meta.(EventCertificateExpiringSoonMeta)
				}

				ctrl, batcherMocks := createBatcherMocks(t)
				t.Cleanup(ctrl.Finish)

				expiryCheckConfig := config.CertificateExpiryMonitorConfig{
					// Let's not provide WarningThresholdDays to test the default fallback
					CheckCooldownSeconds: 60,
					EventCooldownSeconds: 120,
				}

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:               "test-cert-id",
					HoursUntilExpiry: 48,
					NotAfter:         expiry,
					CommonName:       "test-cert",
				})
				require.NoError(t, err)

				batcherMocks.localCacheMock.EXPECT().HasCheckCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsCheckCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().HasFireEventCooldown("test-cert-id").
					Return(true, nil)

				batcherMocks.localCacheMock.EXPECT().IsFireEventCooldownActive("test-cert-id").
					Return(false, nil)

				batcherMocks.localCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(errors.New("set check cooldown in local cache failed"))

				batcherMocks.fallbackCacheMock.EXPECT().SetCheckCooldown("test-cert-id", int64(60)).
					Return(errors.New("set check cooldown in fallback cache failed"))

				batcherMocks.localCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(errors.New("set fire event cooldown in local cache failed"))

				batcherMocks.fallbackCacheMock.EXPECT().SetFireEventCooldown("test-cert-id", int64(120)).
					Return(errors.New("set fire event cooldown in fallback cache failed"))

				ctx, cancel := context.WithCancel(context.Background())
				go batcher.RunInBackground(ctx)

				cancel()
				require.Eventuallyf(t, func() bool {
					<-ctx.Done()
					return true
				}, 5*time.Second, 100*time.Millisecond, "batcher background context was not canceled")

				assert.Equal(t, event.CertificateExpiringSoon, actualFiredEvent)
				assert.Equal(t, EventCertificateExpiringSoonMeta{
					EventMetaDefault: model.EventMetaDefault{
						Message: "Certificate test-cert is expiring in 2 days",
					},
					CertID:        "test-cert-id",
					CertName:      "test-cert",
					ExpiresAt:     expiry,
					DaysRemaining: 2,
					APIID:         "123abc",
				}, actualEventMeta)
			})
		})

	})
}

func TestCertificateExpiryCheckBatcher_composeSoonToExpire(t *testing.T) {
	t.Run("Should compose expiry message with days and hours", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeSoonToExpireMessage(CertInfo{CommonName: "test-cert"}, 5, 10)
		expectedMessage := "Certificate test-cert is expiring in 5 days and 10 hours"
		assert.Equal(t, expectedMessage, actualMessage)
	})

	t.Run("Should compose expiry message with days only", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeSoonToExpireMessage(CertInfo{CommonName: "test-cert"}, 5, 0)
		expectedMessage := "Certificate test-cert is expiring in 5 days"
		assert.Equal(t, expectedMessage, actualMessage)
	})

	t.Run("Should compose expiry message with hours only", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeSoonToExpireMessage(CertInfo{CommonName: "test-cert"}, 0, 2)
		expectedMessage := "Certificate test-cert is expiring in 2 hours"
		assert.Equal(t, expectedMessage, actualMessage)
	})
}

func TestCertificateExpiryCheckBatcher_composeExpiredMessage(t *testing.T) {
	t.Run("Should compose expiry message with days and hours", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeExpiredMessage(CertInfo{CommonName: "test-cert"}, 5, 10)
		expectedMessage := "Certificate test-cert is expired since 5 days and 10 hours"
		assert.Equal(t, expectedMessage, actualMessage)
	})

	t.Run("Should compose expiry message with days only", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeExpiredMessage(CertInfo{CommonName: "test-cert"}, 5, 0)
		expectedMessage := "Certificate test-cert is expired since 5 days"
		assert.Equal(t, expectedMessage, actualMessage)
	})

	t.Run("Should compose expiry message with hours only", func(t *testing.T) {
		batcher := CertificateExpiryCheckBatcher{}
		actualMessage := batcher.composeExpiredMessage(CertInfo{CommonName: "test-cert"}, 0, 2)
		expectedMessage := "Certificate test-cert is expired since 2 hours"
		assert.Equal(t, expectedMessage, actualMessage)
	})
}

func createBatcherMocks(t *testing.T) (ctrl *gomock.Controller, batcherMocks *BatcherMocks) {
	ctrl = gomock.NewController(t)
	logger, _ := logrustest.NewNullLogger()

	return ctrl, &BatcherMocks{
		ctrl:              ctrl,
		logger:            logrus.NewEntry(logger),
		redisStorageMock:  storagemock.NewMockHandler(ctrl),
		localCacheMock:    NewMockCooldownCache(ctrl),
		fallbackCacheMock: NewMockCooldownCache(ctrl),
	}
}
<<<<<<< HEAD
=======

func TestCertInfo_DaysUntilExpiry(t *testing.T) {
	tests := map[string]struct {
		daysUntilExpiry int
		expectedDays    int
		description     string
	}{
		"positive_days": {
			daysUntilExpiry: 30, // 30 days
			expectedDays:    30,
			description:     "Should return 30 days for 30 days",
		},
		"zero_days": {
			daysUntilExpiry: 0,
			expectedDays:    0,
			description:     "Should return 0 days for 0 days",
		},
		"negative_days": {
			daysUntilExpiry: -7, // -7 days (expired)
			expectedDays:    -7,
			description:     "Should return -7 days for -7 days",
		},
		"large_positive": {
			daysUntilExpiry: 365, // 1 year
			expectedDays:    365,
			description:     "Should return 365 days for 365 days",
		},
		"large_negative": {
			daysUntilExpiry: -365, // -1 year
			expectedDays:    -365,
			description:     "Should return -365 days for -365 days",
		},
		"fractional_days_truncated": {
			daysUntilExpiry: 30, // 30.5 days should truncate to 30
			expectedDays:    30,
			description:     "Should return 30 days for 30.5 days (truncated)",
		},
		"one_day": {
			daysUntilExpiry: 1,
			expectedDays:    1,
			description:     "Should return 1 day for 1 day",
		},
		"fractional_day_less_than_one": {
			daysUntilExpiry: 0, // 0.5 days should truncate to 0
			expectedDays:    0,
			description:     "Should return 0 days for 0.5 days (truncated)",
		},
		"half_day": {
			daysUntilExpiry: 0, // 12 hours = 0.5 days, should truncate to 0
			expectedDays:    0,
			description:     "Should return 0 days for 12 hours (0.5 days truncated)",
		},
		"one_and_half_days": {
			daysUntilExpiry: 1, // 36 hours = 1.5 days, should truncate to 1
			expectedDays:    1,
			description:     "Should return 1 day for 36 hours (1.5 days truncated)",
		},
		"two_days": {
			daysUntilExpiry: 2,
			expectedDays:    2,
			description:     "Should return 2 days for 2 days",
		},
		"seven_days": {
			daysUntilExpiry: 7, // 1 week
			expectedDays:    7,
			description:     "Should return 7 days for 1 week",
		},
		"thirty_days": {
			daysUntilExpiry: 30, // 1 month
			expectedDays:    30,
			description:     "Should return 30 days for 1 month",
		},
		"sixty_days": {
			daysUntilExpiry: 60, // 2 months
			expectedDays:    60,
			description:     "Should return 60 days for 2 months",
		},
		"ninety_days": {
			daysUntilExpiry: 90, // 3 months
			expectedDays:    90,
			description:     "Should return 90 days for 3 months",
		},
		"one_hundred_eighty_days": {
			daysUntilExpiry: 180, // 6 months
			expectedDays:    180,
			description:     "Should return 180 days for 6 months",
		},
		"three_hundred_sixty_five_days": {
			daysUntilExpiry: 365, // 1 year
			expectedDays:    365,
			description:     "Should return 365 days for 1 year",
		},
		"seven_hundred_thirty_days": {
			daysUntilExpiry: 730, // 2 years
			expectedDays:    730,
			description:     "Should return 730 days for 2 years",
		},
		"negative_one_day": {
			daysUntilExpiry: -1,
			expectedDays:    -1,
			description:     "Should return -1 day for -1 day",
		},
		"negative_seven_days": {
			daysUntilExpiry: -7, // -1 week
			expectedDays:    -7,
			description:     "Should return -7 days for -1 week",
		},
		"negative_thirty_days": {
			daysUntilExpiry: -30, // -1 month
			expectedDays:    -30,
			description:     "Should return -30 days for -1 month",
		},
		"negative_ninety_days": {
			daysUntilExpiry: -90, // -3 months
			expectedDays:    -90,
			description:     "Should return -90 days for -3 months",
		},
		"negative_three_hundred_sixty_five_days": {
			daysUntilExpiry: -365, // -1 year
			expectedDays:    -365,
			description:     "Should return -365 days for -1 year",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			certInfo := CertInfo{
				ID:          "test-cert",
				CommonName:  "test.example.com",
				NotAfter:    time.Now().Add(time.Duration(tt.daysUntilExpiry) * 24 * time.Hour),
				UntilExpiry: time.Duration(tt.daysUntilExpiry) * 24 * time.Hour,
			}

			result := certInfo.DaysUntilExpiry()
			assert.Equal(t, tt.expectedDays, result, tt.description)
		})
	}
}

func TestApplyConfigDefaults(t *testing.T) {
	t.Run("without provided values", func(t *testing.T) {
		providedCfg := config.CertificateExpiryMonitorConfig{}
		actualCfg := applyConfigDefaults(providedCfg)
		assert.Equal(t, config.DefaultWarningThresholdDays, actualCfg.WarningThresholdDays)
		assert.Equal(t, config.DefaultCheckCooldownSeconds, actualCfg.CheckCooldownSeconds)
		assert.Equal(t, config.DefaultEventCooldownSeconds, actualCfg.EventCooldownSeconds)
	})

	t.Run("with provided values", func(t *testing.T) {
		providedCfg := config.CertificateExpiryMonitorConfig{
			WarningThresholdDays: 10,
			CheckCooldownSeconds: 100,
			EventCooldownSeconds: 1000,
		}
		actualCfg := applyConfigDefaults(providedCfg)
		assert.Equal(t, 10, actualCfg.WarningThresholdDays)
		assert.Equal(t, 100, actualCfg.CheckCooldownSeconds)
		assert.Equal(t, 1000, actualCfg.EventCooldownSeconds)
	})
}
>>>>>>> b06b6aacc... [TT-15869] cooldown defaults not working and minor datetime format adjustments (#7386)
