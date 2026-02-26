package certs

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage"
)

func TestCertificateManager_GetRaw(t *testing.T) {
	t.Run("returns cert from storage", func(t *testing.T) {
		store := storage.NewDummyStorage()
		assert.NoError(t, store.SetKey("raw-cert1", "cert-data-1", 0))

		manager := NewCertificateManager(store, "test", nil, false)

		certData, err := manager.GetRaw("cert1")
		assert.NoError(t, err)
		assert.Equal(t, "cert-data-1", certData)
	})

	t.Run("returns error for missing cert", func(t *testing.T) {
		store := storage.NewDummyStorage()

		manager := NewCertificateManager(store, "test", nil, false)

		certData, err := manager.GetRaw("nonexistent")
		assert.Error(t, err)
		assert.Equal(t, "", certData)
	})
}

func TestCertificateManager_SetCertUsageConfig(t *testing.T) {
	t.Run("does not panic when storage is not MdcbStorage", func(t *testing.T) {
		store := storage.NewDummyStorage()
		logger := logrus.NewEntry(logrus.New())
		manager := &certificateManager{
			storage: store,
			secret:  "test",
			logger:  logger,
		}

		assert.NotPanics(t, func() {
			manager.SetCertUsageConfig(nil, nil)
		})
	})
}
