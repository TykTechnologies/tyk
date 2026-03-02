package certs

import (
	"testing"

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

