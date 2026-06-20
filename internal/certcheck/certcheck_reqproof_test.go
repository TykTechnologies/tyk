package certcheck

import (
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

// Verifies: STK-REQ-042, SYS-REQ-130, SW-REQ-117
// STK-REQ-042:STK-REQ-042-AC-01:acceptance
// STK-REQ-042:STK-REQ-042-AC-03:acceptance
// SYS-REQ-130:nominal:nominal
// MCDC SYS-REQ-130: certificate_expiry_monitor_operation_terminal=T => TRUE
// SW-REQ-117:nominal:nominal
// SW-REQ-117:boundary:nominal
// SW-REQ-117:error_handling:nominal
// SW-REQ-117:determinism:nominal
//
//mcdc:ignore SYS-REQ-130: certificate_expiry_monitor_operation_terminal=F => FALSE -- the onboarded certificate expiry monitor operations are synchronous local helpers that either update local batch state, return cooldown/cache status, classify certificate timing, preserve role/configuration fields, convert durations, or construct event metadata/messages before returning; a non-terminal result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestCertificateExpiryMonitorPreservesLocalBehavior(t *testing.T) {
	t.Run("batch deduplicates and drains queued certificates", func(t *testing.T) {
		batch := NewBatch()
		certs := []CertInfo{
			{ID: "first", CommonName: "first-cert"},
			{ID: "second", CommonName: "second-cert"},
			{ID: "first", CommonName: "duplicate-first-cert"},
		}

		for _, cert := range certs {
			batch.Append(cert)
		}

		require.Equal(t, 2, batch.Size())
		drained := batch.CopyAndClear()
		assert.Equal(t, []CertInfo{certs[0], certs[1]}, drained)
		assert.Equal(t, 0, batch.Size())
	})

	t.Run("expiry classification follows local duration thresholds", func(t *testing.T) {
		tests := []struct {
			name          string
			untilExpiry   time.Duration
			warningDays   int
			wantExpired   bool
			wantExpiring  bool
			wantDayCount  int
			wantHourCount int
		}{
			{name: "expired", untilExpiry: -50 * time.Hour, warningDays: 30, wantExpired: true, wantDayCount: -2, wantHourCount: -50},
			{name: "inside warning threshold", untilExpiry: 48 * time.Hour, warningDays: 30, wantExpiring: true, wantDayCount: 2, wantHourCount: 48},
			{name: "outside warning threshold", untilExpiry: 40 * 24 * time.Hour, warningDays: 30, wantDayCount: 40, wantHourCount: 960},
			{name: "zero duration is expired", untilExpiry: 0, warningDays: 30, wantExpired: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				batcher := &CertificateExpiryCheckBatcher{config: config.CertificateExpiryMonitorConfig{WarningThresholdDays: tt.warningDays}}
				cert := CertInfo{UntilExpiry: tt.untilExpiry}

				assert.Equal(t, tt.wantExpired, batcher.isCertificateExpired(cert))
				assert.Equal(t, tt.wantExpiring, batcher.isCertificateExpiringSoon(cert))
				assert.Equal(t, tt.wantDayCount, cert.DaysUntilExpiry())
				assert.Equal(t, tt.wantHourCount, cert.HoursUntilExpiry())
			})
		}
	})

	t.Run("default configuration and role selection are preserved", func(t *testing.T) {
		tests := []struct {
			name          string
			role          string
			cfg           config.CertificateExpiryMonitorConfig
			wantRole      string
			wantThreshold int
			wantCheck     int
			wantEvent     int
		}{
			{
				name:          "client defaults",
				role:          CertRoleClient,
				wantRole:      CertRoleClient,
				wantThreshold: config.DefaultWarningThresholdDays,
				wantCheck:     config.DefaultCheckCooldownSeconds,
				wantEvent:     config.DefaultEventCooldownSeconds,
			},
			{
				name:          "upstream explicit values",
				role:          CertRoleUpstream,
				cfg:           config.CertificateExpiryMonitorConfig{WarningThresholdDays: 10, CheckCooldownSeconds: 20, EventCooldownSeconds: 30},
				wantRole:      CertRoleUpstream,
				wantThreshold: 10,
				wantCheck:     20,
				wantEvent:     30,
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
					tt.cfg,
					redisStorageMock,
					nil,
					tt.role,
					nil,
					nil,
				)
				require.NoError(t, err)

				assert.Equal(t, tt.wantRole, batcher.certificateRole)
				assert.Equal(t, tt.wantThreshold, batcher.config.WarningThresholdDays)
				assert.Equal(t, tt.wantCheck, batcher.config.CheckCooldownSeconds)
				assert.Equal(t, tt.wantEvent, batcher.config.EventCooldownSeconds)
			})
		}
	})

	t.Run("event helpers preserve role certificate api and message fields", func(t *testing.T) {
		tests := []struct {
			name      string
			expired   bool
			cert      CertInfo
			wantEvent event.Event
			assertion func(*testing.T, any)
		}{
			{
				name:      "expired certificate metadata",
				expired:   true,
				cert:      CertInfo{ID: "cert-expired", CommonName: "expired-cert", NotAfter: time.Unix(100, 0), UntilExpiry: -50 * time.Hour},
				wantEvent: event.CertificateExpired,
				assertion: func(t *testing.T, meta any) {
					got := meta.(EventCertificateExpiredMeta)
					assert.Equal(t, "cert-expired", got.CertID)
					assert.Equal(t, "expired-cert", got.CertName)
					assert.Equal(t, "123abc", got.APIID)
					assert.Equal(t, CertRoleUpstream, got.CertRole)
					assert.Equal(t, 2, got.DaysSinceExpiry)
					assert.Equal(t, "Certificate expired-cert is expired since 2 days and 2 hours", got.Message)
				},
			},
			{
				name:      "expiring soon certificate metadata",
				cert:      CertInfo{ID: "cert-soon", CommonName: "soon-cert", NotAfter: time.Unix(200, 0), UntilExpiry: 49 * time.Hour},
				wantEvent: event.CertificateExpiringSoon,
				assertion: func(t *testing.T, meta any) {
					got := meta.(EventCertificateExpiringSoonMeta)
					assert.Equal(t, "cert-soon", got.CertID)
					assert.Equal(t, "soon-cert", got.CertName)
					assert.Equal(t, "123abc", got.APIID)
					assert.Equal(t, CertRoleUpstream, got.CertRole)
					assert.Equal(t, 2, got.DaysRemaining)
					assert.Equal(t, "Certificate soon-cert is expiring in 2 days and 1 hours", got.Message)
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var fired event.Event
				var meta any
				batcher := &CertificateExpiryCheckBatcher{
					apiMetaData:     testApiMetaData,
					certificateRole: CertRoleUpstream,
					fireEvent: func(evt event.Event, evtMeta any) {
						fired = evt
						meta = evtMeta
					},
					logger: logrus.NewEntry(logrus.New()),
				}

				if tt.expired {
					batcher.handleEventForExpiredCertificate(tt.cert)
				} else {
					batcher.handleEventForSoonToExpireCertificate(tt.cert)
				}

				assert.Equal(t, tt.wantEvent, fired)
				require.NotNil(t, meta)
				tt.assertion(t, meta)
			})
		}
	})
}

// Verifies: STK-REQ-042, SYS-REQ-130, SW-REQ-117
// STK-REQ-042:STK-REQ-042-AC-02:acceptance
// STK-REQ-042:error_handling:negative
// SW-REQ-117:error_handling:negative
func TestCertificateExpiryMonitorCooldownCacheLocalOutcomes(t *testing.T) {
	t.Cleanup(GetCooldownLRUCache().Purge)

	cache, err := NewInMemoryCooldownCache()
	require.NoError(t, err)

	tests := []struct {
		name       string
		set        func() error
		check      func() (bool, error)
		wantActive bool
		wantErr    error
	}{
		{
			name:    "missing check cooldown",
			check:   func() (bool, error) { return cache.IsCheckCooldownActive("missing-check") },
			wantErr: ErrCheckCooldownDoesNotExist,
		},
		{
			name: "active check cooldown",
			set:  func() error { return cache.SetCheckCooldown("active-check", 60) },
			check: func() (bool, error) {
				return cache.IsCheckCooldownActive("active-check")
			},
			wantActive: true,
		},
		{
			name: "expired fire event cooldown",
			set:  func() error { return cache.SetFireEventCooldown("expired-fire", -60) },
			check: func() (bool, error) {
				return cache.IsFireEventCooldownActive("expired-fire")
			},
		},
		{
			name: "active fire event cooldown",
			set:  func() error { return cache.SetFireEventCooldown("active-fire", 60) },
			check: func() (bool, error) {
				return cache.IsFireEventCooldownActive("active-fire")
			},
			wantActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set != nil {
				require.NoError(t, tt.set())
			}
			active, err := tt.check()
			assert.Equal(t, tt.wantActive, active)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
