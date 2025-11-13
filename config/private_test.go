package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrivate_GetOAuthTokensPurgeInterval(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		p := Private{}
		assert.Equal(t, time.Hour, p.GetOAuthTokensPurgeInterval())
	})

	t.Run("custom value", func(t *testing.T) {
		p := Private{OAuthTokensPurgeInterval: 5}
		assert.Equal(t, time.Second*5, p.GetOAuthTokensPurgeInterval())
	})
}
