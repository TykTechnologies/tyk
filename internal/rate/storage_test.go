package rate

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func TestNewStorage(t *testing.T) {
	conf, err := config.NewDefaultWithEnv()
	assert.NoError(t, err)

	// Coverage
	conf.Storage.MaxActive = 100
	conf.Storage.Timeout = 4
	conf.Storage.UseSSL = true

	client := NewStorage(&conf.Storage)
	assert.NotNil(t, client)
}
