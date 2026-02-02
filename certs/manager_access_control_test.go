package certs

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage"
)

// mockUsageTracker implements UsageTracker for testing
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

func TestCertificateManager_GetRaw_AccessControl(t *testing.T) {
	t.Run("selective sync disabled - all certificates accessible", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		assert.NoError(t, storage.SetKey("raw-cert1", "cert-data-1", 0))

		manager := NewCertificateManager(storage, "test", nil, false)

		// Should be accessible even without registry
		certData, err := manager.GetRaw("cert1")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-1", certData)
	})

	t.Run("selective sync enabled - required certificate accessible", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		assert.NoError(t, storage.SetKey("raw-cert1", "cert-data-1", 0))

		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage:       storage,
			secret:        "test",
			logger:        logger,
			selectiveSync: true,
			registry: &mockUsageTracker{
				requiredCerts: map[string]bool{
					"cert1": true,
				},
			},
		}

		certData, err := manager.GetRaw("cert1")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-1", certData)
	})

	t.Run("selective sync enabled - non-required certificate blocked", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		assert.NoError(t, storage.SetKey("raw-cert1", "cert-data-1", 0))

		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage:       storage,
			secret:        "test",
			logger:        logger,
			selectiveSync: true,
			registry: &mockUsageTracker{
				requiredCerts: map[string]bool{
					"cert2": true, // cert1 not in required list
				},
			},
		}

		certData, err := manager.GetRaw("cert1")
		assert.Error(t, err)
		assert.Equal(t, "", certData)
		assert.Contains(t, err.Error(), "certificate not required by loaded APIs")
	})

	t.Run("selective sync enabled - nil registry allows access", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		assert.NoError(t, storage.SetKey("raw-cert1", "cert-data-1", 0))

		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage:       storage,
			secret:        "test",
			logger:        logger,
			selectiveSync: true,
			registry:      nil, // nil registry
		}

		// Should be accessible with nil registry (fallback to legacy behavior)
		certData, err := manager.GetRaw("cert1")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-1", certData)
	})

	t.Run("selective sync enabled - multiple certificates", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		assert.NoError(t, storage.SetKey("raw-cert1", "cert-data-1", 0))
		assert.NoError(t, storage.SetKey("raw-cert2", "cert-data-2", 0))
		assert.NoError(t, storage.SetKey("raw-cert3", "cert-data-3", 0))

		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage:       storage,
			secret:        "test",
			logger:        logger,
			selectiveSync: true,
			registry: &mockUsageTracker{
				requiredCerts: map[string]bool{
					"cert1": true,
					"cert3": true,
					// cert2 not required
				},
			},
		}

		// cert1 should be accessible
		certData, err := manager.GetRaw("cert1")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-1", certData)

		// cert2 should be blocked
		certData, err = manager.GetRaw("cert2")
		assert.Error(t, err)
		assert.Equal(t, "", certData)

		// cert3 should be accessible
		certData, err = manager.GetRaw("cert3")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-3", certData)
	})
}

func TestCertificateManager_SetUsageTracker(t *testing.T) {
	t.Run("set registry successfully", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage: storage,
			secret:  "test",
			logger:  logger,
		}

		registry := &mockUsageTracker{
			requiredCerts: map[string]bool{
				"cert1": true,
			},
		}

		manager.SetUsageTracker(registry, nil)

		assert.NotNil(t, manager.registry)
		assert.True(t, manager.selectiveSync)
	})

	t.Run("set nil registry", func(t *testing.T) {
		storage := storage.NewDummyStorage()
		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage: storage,
			secret:  "test",
			logger:  logger,
		}

		manager.SetUsageTracker(nil, nil)

		assert.Nil(t, manager.registry)
		assert.True(t, manager.selectiveSync)
	})
}
