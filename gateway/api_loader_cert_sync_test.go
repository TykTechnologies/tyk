package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
)

// newSyncTestGateway builds a minimal Gateway (no Redis) suitable for
// testing syncRequiredCertificates.
func newSyncTestGateway(t *testing.T, useRPC, syncUsedCertsOnly bool) *Gateway {
	t.Helper()
	cfg := config.Config{}
	cfg.SlaveOptions.UseRPC = useRPC
	cfg.SlaveOptions.SyncUsedCertsOnly = syncUsedCertsOnly
	return NewGateway(cfg, context.Background())
}

// TestSyncRequiredCertificates_Unit tests the catch-up cert sync logic without Redis.
func TestSyncRequiredCertificates_Unit(t *testing.T) {
	t.Run("no-op when tracker is nil", func(t *testing.T) {
		gw := newSyncTestGateway(t, true, true)
		gw.certUsageTracker = nil
		// Should not panic
		assert.NotPanics(t, func() {
			gw.syncRequiredCertificates()
		})
	})

	t.Run("no-op when UseRPC is false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		gw := newSyncTestGateway(t, false, true)
		gw.certUsageTracker = newUsageTracker()
		gw.certUsageTracker.ReplaceAll(map[string]map[string]struct{}{
			"cert1": {"api1": {}},
		})

		mockCertMgr := mock.NewMockCertificateManager(ctrl)
		gw.CertificateManager = mockCertMgr

		// GetRaw must NOT be called
		mockCertMgr.EXPECT().GetRaw(gomock.Any()).Times(0)

		gw.syncRequiredCertificates()
	})

	t.Run("no-op when SyncUsedCertsOnly is false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		gw := newSyncTestGateway(t, true, false)
		gw.certUsageTracker = newUsageTracker()
		gw.certUsageTracker.ReplaceAll(map[string]map[string]struct{}{
			"cert1": {"api1": {}},
		})

		mockCertMgr := mock.NewMockCertificateManager(ctrl)
		gw.CertificateManager = mockCertMgr

		// GetRaw must NOT be called
		mockCertMgr.EXPECT().GetRaw(gomock.Any()).Times(0)

		gw.syncRequiredCertificates()
	})

	t.Run("no-op when tracker is empty", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		gw := newSyncTestGateway(t, true, true)
		gw.certUsageTracker = newUsageTracker()

		mockCertMgr := mock.NewMockCertificateManager(ctrl)
		gw.CertificateManager = mockCertMgr

		// GetRaw must NOT be called
		mockCertMgr.EXPECT().GetRaw(gomock.Any()).Times(0)

		gw.syncRequiredCertificates()
	})

	t.Run("calls GetRaw for each required cert", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		gw := newSyncTestGateway(t, true, true)
		gw.certUsageTracker = newUsageTracker()
		gw.certUsageTracker.ReplaceAll(map[string]map[string]struct{}{
			"cert1": {"api1": {}},
			"cert2": {"api1": {}, "api2": {}},
			"cert3": {"api2": {}},
		})

		mockCertMgr := mock.NewMockCertificateManager(ctrl)
		gw.CertificateManager = mockCertMgr

		// Each cert should trigger exactly one GetRaw call
		mockCertMgr.EXPECT().GetRaw("cert1").Return("raw-cert1", nil).Times(1)
		mockCertMgr.EXPECT().GetRaw("cert2").Return("raw-cert2", nil).Times(1)
		mockCertMgr.EXPECT().GetRaw("cert3").Return("raw-cert3", nil).Times(1)

		gw.syncRequiredCertificates()
	})

	t.Run("continues on GetRaw error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		gw := newSyncTestGateway(t, true, true)
		gw.certUsageTracker = newUsageTracker()
		gw.certUsageTracker.ReplaceAll(map[string]map[string]struct{}{
			"cert1": {"api1": {}},
			"cert2": {"api1": {}},
		})

		mockCertMgr := mock.NewMockCertificateManager(ctrl)
		gw.CertificateManager = mockCertMgr

		// cert1 fails, cert2 succeeds — both must be attempted
		mockCertMgr.EXPECT().GetRaw("cert1").Return("", errors.New("not found")).AnyTimes()
		mockCertMgr.EXPECT().GetRaw("cert2").Return("raw-cert2", nil).AnyTimes()

		// Should not panic despite the error
		assert.NotPanics(t, func() {
			gw.syncRequiredCertificates()
		})
	})
}
