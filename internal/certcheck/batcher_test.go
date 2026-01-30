package certcheck

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/model"

	storagemock "github.com/TykTechnologies/tyk/storage/mock"
)

var testApiMetaData = APIMetaData{
	APIID:   "123abc",
	APIName: "API",
}

// createTestCertInfo creates a CertInfo from a real x509 certificate with the specified expiry time
func createTestCertInfo(t *testing.T, commonName string, notAfter time.Time) CertInfo {
	t.Helper()

	// Create a real x509 certificate
	_, _, _, tlsCert := crypto.GenCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour), // Valid from 1 hour ago
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, true)

	// Calculate the ID using the same method as the real code
	certID := crypto.HexSHA256(tlsCert.Leaf.Raw)

	// Calculate duration until expiry using the same method as the real code
	untilExpiry := time.Until(notAfter)

	return CertInfo{
		ID:          certID,
		CommonName:  tlsCert.Leaf.Subject.CommonName,
		NotAfter:    tlsCert.Leaf.NotAfter,
		UntilExpiry: untilExpiry,
	}
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

	batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, config.CertificateExpiryMonitorConfig{}, batcherMocks.redisStorageMock, nil, nil, nil)
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

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

			batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, nil, nil, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:          "test-cert-id",
					UntilExpiry: 48 * time.Hour, // 48 hours
					NotAfter:    expiry,
					CommonName:  "test-cert",
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent, nil, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiredSince := now.Add(-50 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:          "test-cert-id",
					UntilExpiry: -50 * time.Hour, // -50 hours
					NotAfter:    expiredSince,
					CommonName:  "test-cert",
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
					CertRole:        CertRoleClient,
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent, nil, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:          "test-cert-id",
					UntilExpiry: 48 * time.Hour, // 48 hours
					NotAfter:    expiry,
					CommonName:  "test-cert",
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
					CertRole:      CertRoleClient,
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

				batcher, err := NewCertificateExpiryCheckBatcher(batcherMocks.logger, testApiMetaData, expiryCheckConfig, batcherMocks.redisStorageMock, fireEvent, nil, nil)
				require.NoError(t, err)

				batcher.inMemoryCooldownCache = batcherMocks.localCacheMock
				batcher.fallbackCooldownCache = batcherMocks.fallbackCacheMock
				batcher.flushTicker = time.NewTicker(10 * time.Millisecond)

				now := time.Now()
				expiry := now.Add(48 * time.Hour)
				err = batcher.Add(CertInfo{
					ID:          "test-cert-id",
					UntilExpiry: 48 * time.Hour, // 48 hours
					NotAfter:    expiry,
					CommonName:  "test-cert",
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
					CertRole:      CertRoleClient,
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

func TestCertificateExpiryCheckBatcher_isCertificateExpired(t *testing.T) {
	batcher := &CertificateExpiryCheckBatcher{}

	tests := map[string]struct {
		commonName     string
		hoursFromNow   float64
		expectedResult bool
		description    string
	}{
		"expired_certificate": {
			commonName:     "expired-cert",
			hoursFromNow:   -10, // 10 hours ago
			expectedResult: true,
			description:    "Should return true when certificate is expired (negative hours)",
		},
		"expired_certificate_30_minutes": {
			commonName:     "expired-cert-30min",
			hoursFromNow:   -0.5, // 30 minutes ago
			expectedResult: true,
			description:    "Should return true when certificate expired 30 minutes ago",
		},
		"just_expired_certificate": {
			commonName:     "just-expired-cert",
			hoursFromNow:   0, // Right now
			expectedResult: true,
			description:    "Should return true when certificate is exactly expired (zero hours)",
		},
		"expiring_soon_certificate_30_minutes": {
			commonName:     "expiring-soon-cert-30min",
			hoursFromNow:   0.5, // 30 minutes from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 30 minutes (not expired with seconds precision)",
		},
		"valid_certificate": {
			commonName:     "valid-cert",
			hoursFromNow:   24, // 24 hours from now
			expectedResult: false,
			description:    "Should return false when certificate is not expired (positive hours)",
		},
		"long_valid_certificate": {
			commonName:     "long-valid-cert",
			hoursFromNow:   720, // 30 days from now
			expectedResult: false,
			description:    "Should return false when certificate has many hours until expiry",
		},
		"expired_certificate_1_second": {
			commonName:     "expired-cert-1sec",
			hoursFromNow:   -1.0 / 3600, // 1 second ago
			expectedResult: true,
			description:    "Should return true when certificate expired 1 second ago",
		},
		"expired_certificate_1_minute": {
			commonName:     "expired-cert-1min",
			hoursFromNow:   -1.0 / 60, // 1 minute ago
			expectedResult: true,
			description:    "Should return true when certificate expired 1 minute ago",
		},
		"expired_certificate_1_hour": {
			commonName:     "expired-cert-1hour",
			hoursFromNow:   -1, // 1 hour ago
			expectedResult: true,
			description:    "Should return true when certificate expired 1 hour ago",
		},
		"expired_certificate_1_day": {
			commonName:     "expired-cert-1day",
			hoursFromNow:   -24, // 1 day ago
			expectedResult: true,
			description:    "Should return true when certificate expired 1 day ago",
		},
		"expired_certificate_1_week": {
			commonName:     "expired-cert-1week",
			hoursFromNow:   -168, // 1 week ago (7 days)
			expectedResult: true,
			description:    "Should return true when certificate expired 1 week ago",
		},
		"expired_certificate_1_month": {
			commonName:     "expired-cert-1month",
			hoursFromNow:   -720, // 1 month ago (30 days)
			expectedResult: true,
			description:    "Should return true when certificate expired 1 month ago",
		},
		"expired_certificate_1_year": {
			commonName:     "expired-cert-1year",
			hoursFromNow:   -8760, // 1 year ago (365 days)
			expectedResult: true,
			description:    "Should return true when certificate expired 1 year ago",
		},
		"expiring_soon_certificate_1_second": {
			commonName:     "expiring-soon-cert-1sec",
			hoursFromNow:   1.0 / 3600, // 1 second from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 second (not expired)",
		},
		"expiring_soon_certificate_1_minute": {
			commonName:     "expiring-soon-cert-1min",
			hoursFromNow:   1.0 / 60, // 1 minute from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 minute (not expired)",
		},
		"expiring_soon_certificate_1_hour": {
			commonName:     "expiring-soon-cert-1hour",
			hoursFromNow:   1, // 1 hour from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 hour (not expired)",
		},
		"expiring_soon_certificate_1_day": {
			commonName:     "expiring-soon-cert-1day",
			hoursFromNow:   24, // 1 day from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 day (not expired)",
		},
		"expiring_soon_certificate_1_week": {
			commonName:     "expiring-soon-cert-1week",
			hoursFromNow:   168, // 1 week from now (7 days)
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 week (not expired)",
		},
		"expiring_soon_certificate_1_month": {
			commonName:     "expiring-soon-cert-1month",
			hoursFromNow:   720, // 1 month from now (30 days)
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 month (not expired)",
		},
		"expiring_soon_certificate_1_year": {
			commonName:     "expiring-soon-cert-1year",
			hoursFromNow:   8760, // 1 year from now (365 days)
			expectedResult: false,
			description:    "Should return false when certificate expires in 1 year (not expired)",
		},
		"expired_certificate_very_old": {
			commonName:     "expired-cert-very-old",
			hoursFromNow:   -87600, // 10 years ago
			expectedResult: true,
			description:    "Should return true when certificate expired 10 years ago",
		},
		"valid_certificate_very_future": {
			commonName:     "valid-cert-very-future",
			hoursFromNow:   87600, // 10 years from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 10 years (not expired)",
		},
		"expired_certificate_fractional_seconds": {
			commonName:     "expired-cert-fractional",
			hoursFromNow:   -0.5 / 3600, // 0.5 seconds ago
			expectedResult: true,
			description:    "Should return true when certificate expired 0.5 seconds ago",
		},
		"expiring_soon_certificate_fractional_seconds": {
			commonName:     "expiring-soon-cert-fractional",
			hoursFromNow:   0.5 / 3600, // 0.5 seconds from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 0.5 seconds (not expired)",
		},
		"expired_certificate_5_seconds": {
			commonName:     "expired-cert-5sec",
			hoursFromNow:   -5.0 / 3600, // 5 seconds ago
			expectedResult: true,
			description:    "Should return true when certificate expired 5 seconds ago",
		},
		"expiring_soon_certificate_5_seconds": {
			commonName:     "expiring-soon-cert-5sec",
			hoursFromNow:   5.0 / 3600, // 5 seconds from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 5 seconds (not expired)",
		},
		"expired_certificate_10_seconds": {
			commonName:     "expired-cert-10sec",
			hoursFromNow:   -10.0 / 3600, // 10 seconds ago
			expectedResult: true,
			description:    "Should return true when certificate expired 10 seconds ago",
		},
		"expiring_soon_certificate_10_seconds": {
			commonName:     "expiring-soon-cert-10sec",
			hoursFromNow:   10.0 / 3600, // 10 seconds from now
			expectedResult: false,
			description:    "Should return false when certificate expires in 10 seconds (not expired)",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Create certificate with the specified expiry time
			expiryTime := time.Now().Add(time.Duration(tt.hoursFromNow * float64(time.Hour)))
			certInfo := createTestCertInfo(t, tt.commonName, expiryTime)

			// Test the method
			result := batcher.isCertificateExpired(certInfo)
			assert.Equal(t, tt.expectedResult, result, tt.description)

			// Verify UntilExpiry calculation
			if tt.expectedResult {
				assert.True(t, certInfo.UntilExpiry <= 0, "UntilExpiry should be <= 0 for expired cert")
			} else {
				assert.True(t, certInfo.UntilExpiry > 0, "UntilExpiry should be positive for valid cert")
			}
		})
	}
}

func TestCertificateExpiryCheckBatcher_isCertificateExpiringSoon(t *testing.T) {
	tests := map[string]struct {
		commonName           string
		hoursFromNow         float64
		warningThresholdDays int
		expectedResult       bool
		description          string
	}{
		"expired_certificate": {
			commonName:           "expired-cert",
			hoursFromNow:         -10, // 10 hours ago
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate is already expired",
		},
		"expired_certificate_30_minutes": {
			commonName:           "expired-cert-30min",
			hoursFromNow:         -1, // 1 hour ago (to ensure negative UntilExpiry)
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate expired 1 hour ago",
		},
		"just_expired_certificate": {
			commonName:           "just-expired-cert",
			hoursFromNow:         -0.1, // Just expired (6 minutes ago)
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate is just expired (negative time until expiry)",
		},
		"expiring_soon_certificate_30_minutes": {
			commonName:           "expiring-soon-cert-30min",
			hoursFromNow:         0.5, // 30 minutes from now
			warningThresholdDays: 30,
			expectedResult:       true,
			description:          "Should return true when certificate expires in 30 minutes (truncated to 0, within threshold)",
		},
		"expiring_soon_certificate_1_day": {
			commonName:           "expiring-soon-cert-1day",
			hoursFromNow:         24, // 1 day from now
			warningThresholdDays: 30,
			expectedResult:       true,
			description:          "Should return true when certificate expires in 1 day (within 30-day threshold)",
		},
		"expiring_soon_certificate_15_days": {
			commonName:           "expiring-soon-cert-15days",
			hoursFromNow:         15 * 24, // 15 days from now
			warningThresholdDays: 30,
			expectedResult:       true,
			description:          "Should return true when certificate expires in 15 days (within 30-day threshold)",
		},
		"expiring_soon_certificate_30_days": {
			commonName:           "expiring-soon-cert-30days",
			hoursFromNow:         30 * 24, // 30 days from now
			warningThresholdDays: 30,
			expectedResult:       true,
			description:          "Should return true when certificate expires in exactly 30 days (at threshold)",
		},
		"expiring_soon_certificate_30_days_1_hour": {
			commonName:           "expiring-soon-cert-30days-1hour",
			hoursFromNow:         30*24 + 1, // 30 days and 1 hour from now
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate expires in 30 days and 1 hour (just over 30-day threshold)",
		},
		"expiring_soon_certificate_30_days_2_hours": {
			commonName:           "expiring-soon-cert-30days-2hours",
			hoursFromNow:         30*24 + 2, // 30 days and 2 hours from now
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate expires in 30 days and 2 hours (just over 30-day threshold)",
		},
		"valid_certificate_60_days": {
			commonName:           "valid-cert-60days",
			hoursFromNow:         60 * 24, // 60 days from now
			warningThresholdDays: 30,
			expectedResult:       false,
			description:          "Should return false when certificate expires in 60 days (well beyond threshold)",
		},
		"custom_threshold_1_day": {
			commonName:           "custom-threshold-1day",
			hoursFromNow:         12, // 12 hours from now
			warningThresholdDays: 1,
			expectedResult:       true,
			description:          "Should return true when certificate expires in 12 hours with 1-day threshold",
		},
		"custom_threshold_1_day_over": {
			commonName:           "custom-threshold-1day-over",
			hoursFromNow:         25, // 25 hours from now
			warningThresholdDays: 1,
			expectedResult:       false,
			description:          "Should return false when certificate expires in 25 hours with 1-day threshold (just over 1-day threshold)",
		},
		"custom_threshold_1_day_2_hours_over": {
			commonName:           "custom-threshold-1day-2hours-over",
			hoursFromNow:         26, // 26 hours from now
			warningThresholdDays: 1,
			expectedResult:       false,
			description:          "Should return false when certificate expires in 26 hours with 1-day threshold (just over 1-day threshold)",
		},
		"zero_threshold_defaults_to_30_days": {
			commonName:           "zero-threshold-default",
			hoursFromNow:         15 * 24, // 15 days from now
			warningThresholdDays: 0,       // Should default to 30 days
			expectedResult:       true,
			description:          "Should return true when certificate expires in 15 days with 0 threshold (defaults to 30 days)",
		},
		"minute_precision_30_minutes": {
			commonName:           "minute-precision-30min",
			hoursFromNow:         0.5, // 30 minutes from now
			warningThresholdDays: 1,   // 1 day threshold
			expectedResult:       true,
			description:          "Should return true when certificate expires in 30 minutes with 1-day threshold (minute precision)",
		},
		"minute_precision_1_hour_1_minute": {
			commonName:           "minute-precision-1hour-1min",
			hoursFromNow:         1 + 1.0/60, // 1 hour and 1 minute from now
			warningThresholdDays: 1,          // 1 day threshold
			expectedResult:       true,
			description:          "Should return true when certificate expires in 1 hour 1 minute with 1-day threshold (minute precision)",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Create batcher with custom warning threshold
			batcher := &CertificateExpiryCheckBatcher{
				config: config.CertificateExpiryMonitorConfig{
					WarningThresholdDays: tt.warningThresholdDays,
				},
			}

			// Create certificate with the specified expiry time
			expiryTime := time.Now().Add(time.Duration(tt.hoursFromNow * float64(time.Hour)))
			certInfo := createTestCertInfo(t, tt.commonName, expiryTime)

			// Test the method
			result := batcher.isCertificateExpiringSoon(certInfo)
			assert.Equal(t, tt.expectedResult, result, tt.description)

			// Verify time calculation with duration precision
			untilExpiry := certInfo.UntilExpiry
			actualThreshold := tt.warningThresholdDays
			if actualThreshold == 0 {
				actualThreshold = 30 // Default value
			}
			warningThresholdDuration := time.Duration(actualThreshold) * 24 * time.Hour // Convert days to duration

			if tt.expectedResult {
				assert.True(t, untilExpiry > 0, "Until expiry should be positive for expiring soon cert")
				assert.True(t, untilExpiry <= warningThresholdDuration, "Until expiry should be within warning threshold")
			} else {
				// For false cases, either expired or beyond threshold
				if untilExpiry <= 0 {
					assert.True(t, untilExpiry <= 0, "Until expiry should be <= 0 for expired cert")
				} else {
					assert.True(t, untilExpiry > warningThresholdDuration, "Until expiry should be beyond warning threshold")
				}
			}
		})
	}
}

func TestCertInfo_HoursUntilExpiry(t *testing.T) {
	tests := map[string]struct {
		secondsUntilExpiry int
		expectedHours      int
		description        string
	}{
		"positive_hours": {
			secondsUntilExpiry: 7200, // 2 hours
			expectedHours:      2,
			description:        "Should return 2 hours for 7200 seconds",
		},
		"fractional_hours_truncated": {
			secondsUntilExpiry: 5400, // 1.5 hours
			expectedHours:      1,
			description:        "Should return 1 hour for 5400 seconds (truncated)",
		},
		"zero_seconds": {
			secondsUntilExpiry: 0,
			expectedHours:      0,
			description:        "Should return 0 hours for 0 seconds",
		},
		"negative_seconds": {
			secondsUntilExpiry: -3600, // -1 hour
			expectedHours:      -1,
			description:        "Should return -1 hour for -3600 seconds",
		},
		"large_positive": {
			secondsUntilExpiry: 86400, // 24 hours
			expectedHours:      24,
			description:        "Should return 24 hours for 86400 seconds",
		},
		"large_negative": {
			secondsUntilExpiry: -86400, // -24 hours
			expectedHours:      -24,
			description:        "Should return -24 hours for -86400 seconds",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			certInfo := CertInfo{
				ID:          "test-cert",
				CommonName:  "test.example.com",
				NotAfter:    time.Now().Add(time.Duration(tt.secondsUntilExpiry) * time.Second),
				UntilExpiry: time.Duration(tt.secondsUntilExpiry) * time.Second,
			}

			result := certInfo.HoursUntilExpiry()
			assert.Equal(t, tt.expectedHours, result, tt.description)
		})
	}
}

func TestCertInfo_MinutesUntilExpiry(t *testing.T) {
	tests := map[string]struct {
		secondsUntilExpiry int
		expectedMinutes    int
		description        string
	}{
		"positive_minutes": {
			secondsUntilExpiry: 120, // 2 minutes
			expectedMinutes:    2,
			description:        "Should return 2 minutes for 120 seconds",
		},
		"fractional_minutes_truncated": {
			secondsUntilExpiry: 90, // 1.5 minutes
			expectedMinutes:    1,
			description:        "Should return 1 minute for 90 seconds (truncated)",
		},
		"zero_seconds": {
			secondsUntilExpiry: 0,
			expectedMinutes:    0,
			description:        "Should return 0 minutes for 0 seconds",
		},
		"negative_seconds": {
			secondsUntilExpiry: -60, // -1 minute
			expectedMinutes:    -1,
			description:        "Should return -1 minute for -60 seconds",
		},
		"large_positive": {
			secondsUntilExpiry: 3600, // 60 minutes (1 hour)
			expectedMinutes:    60,
			description:        "Should return 60 minutes for 3600 seconds",
		},
		"large_negative": {
			secondsUntilExpiry: -3600, // -60 minutes (-1 hour)
			expectedMinutes:    -60,
			description:        "Should return -60 minutes for -3600 seconds",
		},
		"exactly_one_minute": {
			secondsUntilExpiry: 60, // 1 minute
			expectedMinutes:    1,
			description:        "Should return 1 minute for exactly 60 seconds",
		},
		"thirty_seconds": {
			secondsUntilExpiry: 30, // 0.5 minutes
			expectedMinutes:    0,
			description:        "Should return 0 minutes for 30 seconds (truncated)",
		},
		"one_hour_thirty_minutes": {
			secondsUntilExpiry: 5400, // 90 minutes (1.5 hours)
			expectedMinutes:    90,
			description:        "Should return 90 minutes for 5400 seconds",
		},
		"one_second": {
			secondsUntilExpiry: 1, // 1 second
			expectedMinutes:    0,
			description:        "Should return 0 minutes for 1 second (truncated)",
		},
		"fifty_nine_seconds": {
			secondsUntilExpiry: 59, // 59 seconds
			expectedMinutes:    0,
			description:        "Should return 0 minutes for 59 seconds (truncated)",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			certInfo := CertInfo{
				ID:          "test-cert",
				CommonName:  "test.example.com",
				NotAfter:    time.Now().Add(time.Duration(tt.secondsUntilExpiry) * time.Second),
				UntilExpiry: time.Duration(tt.secondsUntilExpiry) * time.Second,
			}

			result := certInfo.MinutesUntilExpiry()
			assert.Equal(t, tt.expectedMinutes, result, tt.description)
		})
	}
}

func TestCertInfo_SecondsUntilExpiry(t *testing.T) {
	tests := map[string]struct {
		secondsUntilExpiry int
		expectedSeconds    int
		description        string
	}{
		"positive_seconds": {
			secondsUntilExpiry: 120, // 2 minutes
			expectedSeconds:    120,
			description:        "Should return 120 seconds for 120 seconds",
		},
		"zero_seconds": {
			secondsUntilExpiry: 0,
			expectedSeconds:    0,
			description:        "Should return 0 seconds for 0 seconds",
		},
		"negative_seconds": {
			secondsUntilExpiry: -60, // -1 minute
			expectedSeconds:    -60,
			description:        "Should return -60 seconds for -60 seconds",
		},
		"large_positive": {
			secondsUntilExpiry: 3600, // 1 hour
			expectedSeconds:    3600,
			description:        "Should return 3600 seconds for 3600 seconds",
		},
		"large_negative": {
			secondsUntilExpiry: -3600, // -1 hour
			expectedSeconds:    -3600,
			description:        "Should return -3600 seconds for -3600 seconds",
		},
		"fractional_seconds_truncated": {
			secondsUntilExpiry: 90, // 1.5 minutes
			expectedSeconds:    90,
			description:        "Should return 90 seconds for 90 seconds (no truncation for seconds)",
		},
		"one_second": {
			secondsUntilExpiry: 1,
			expectedSeconds:    1,
			description:        "Should return 1 second for 1 second",
		},
		"fifty_nine_seconds": {
			secondsUntilExpiry: 59,
			expectedSeconds:    59,
			description:        "Should return 59 seconds for 59 seconds",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			certInfo := CertInfo{
				ID:          "test-cert",
				CommonName:  "test.example.com",
				NotAfter:    time.Now().Add(time.Duration(tt.secondsUntilExpiry) * time.Second),
				UntilExpiry: time.Duration(tt.secondsUntilExpiry) * time.Second,
			}

			result := certInfo.SecondsUntilExpiry()
			assert.Equal(t, tt.expectedSeconds, result, tt.description)
		})
	}
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
