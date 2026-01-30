package storage

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage/mock"
)

// mockUsageTracker implements certUsageTracker for testing
type mockUsageTracker struct {
	requiredCerts map[string]bool
}

func (m *mockUsageTracker) Required(certID string) bool {
	if m.requiredCerts == nil {
		return false
	}
	return m.requiredCerts[certID]
}

func (m *mockUsageTracker) APIs(certID string) []string {
	return nil
}

func TestMdcbStorage_GetKey_CertificateFiltering(t *testing.T) {
	getLogger := func() *logrus.Entry {
		logger := logrus.New()
		logger.SetOutput(logrus.StandardLogger().Out)
		return logger.WithField("test", "cert_filtering")
	}

	t.Run("feature disabled - all certificates pulled", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		// Feature disabled (nil config)
		m := NewMdcbStorage(local, remote, log, nil, nil, nil)

		certKey := "raw-cert123"
		remote.EXPECT().GetKey(certKey).Return("cert-data", nil)

		val, err := m.GetKey(certKey)
		assert.NoError(t, err)
		assert.Equal(t, "cert-data", val)
	})

	t.Run("feature enabled - required certificate pulled", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		cfg := &config.Config{
			SlaveOptions: config.SlaveOptionsConfig{
				UseRPC:            true,
				SyncUsedCertsOnly: true,
			},
		}

		registry := &mockUsageTracker{
			requiredCerts: map[string]bool{
				"cert123": true,
			},
		}

		m := NewMdcbStorage(local, remote, log, nil, registry, cfg)

		certKey := "raw-cert123"
		remote.EXPECT().GetKey(certKey).Return("cert-data", nil)

		val, err := m.GetKey(certKey)
		assert.NoError(t, err)
		assert.Equal(t, "cert-data", val)
	})

	t.Run("feature enabled - non-required certificate blocked", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		cfg := &config.Config{
			SlaveOptions: config.SlaveOptionsConfig{
				UseRPC:            true,
				SyncUsedCertsOnly: true,
			},
		}

		registry := &mockUsageTracker{
			requiredCerts: map[string]bool{
				"cert456": true, // cert123 not in required list
			},
		}

		m := NewMdcbStorage(local, remote, log, nil, registry, cfg)

		certKey := "raw-cert123"
		// Should NOT call GetKey on remote - no EXPECT set

		val, err := m.GetKey(certKey)
		assert.Error(t, err)
		assert.Equal(t, "", val)
		assert.Contains(t, err.Error(), "certificate not required")
	})

	t.Run("feature enabled - nil registry allows all", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		cfg := &config.Config{
			SlaveOptions: config.SlaveOptionsConfig{
				UseRPC:            true,
				SyncUsedCertsOnly: true,
			},
		}

		m := NewMdcbStorage(local, remote, log, nil, nil, cfg)

		certKey := "raw-cert123"
		remote.EXPECT().GetKey(certKey).Return("cert-data", nil)

		val, err := m.GetKey(certKey)
		assert.NoError(t, err)
		assert.Equal(t, "cert-data", val)
	})

	t.Run("feature enabled - non-certificate keys not filtered", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		cfg := &config.Config{
			SlaveOptions: config.SlaveOptionsConfig{
				UseRPC:            true,
				SyncUsedCertsOnly: true,
			},
		}

		registry := &mockUsageTracker{
			requiredCerts: map[string]bool{}, // Empty - no certs required
		}

		m := NewMdcbStorage(local, remote, log, nil, registry, cfg)

		// Non-certificate keys should not be filtered
		apiKey := "apikey-abc123"
		remote.EXPECT().GetKey(apiKey).Return("api-data", nil)

		val, err := m.GetKey(apiKey)
		assert.NoError(t, err)
		assert.Equal(t, "api-data", val)
	})

	t.Run("sync_used_certs_only disabled - certificates not filtered", func(t *testing.T) {
		ctrlRemote := gomock.NewController(t)
		defer ctrlRemote.Finish()

		remote := mock.NewMockHandler(ctrlRemote)
		local := NewDummyStorage()
		log := getLogger()

		cfg := &config.Config{
			SlaveOptions: config.SlaveOptionsConfig{
				UseRPC:            true,
				SyncUsedCertsOnly: false, // Feature disabled
			},
		}

		registry := &mockUsageTracker{
			requiredCerts: map[string]bool{}, // Empty - no certs required
		}

		m := NewMdcbStorage(local, remote, log, nil, registry, cfg)

		certKey := "raw-cert123"
		remote.EXPECT().GetKey(certKey).Return("cert-data", nil)

		val, err := m.GetKey(certKey)
		assert.NoError(t, err)
		assert.Equal(t, "cert-data", val)
	})
}
