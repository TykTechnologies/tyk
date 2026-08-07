package oauth2common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDerivedTTL_ExpiresInWins(t *testing.T) {
	ttl := DerivedTTL(10*time.Second, 0, time.Hour, time.Second)
	assert.Equal(t, 9*time.Second, ttl)
}

func TestDerivedTTL_InboundRemainingWins(t *testing.T) {
	ttl := DerivedTTL(time.Hour, 30*time.Second, 0, 5*time.Second)
	assert.Equal(t, 25*time.Second, ttl)
}

func TestDerivedTTL_MaxTimeoutWins(t *testing.T) {
	ttl := DerivedTTL(time.Hour, 24*time.Hour, 5*time.Minute, 30*time.Second)
	assert.Equal(t, 4*time.Minute+30*time.Second, ttl)
}

func TestStaticTTL_TimeoutWins(t *testing.T) {
	ttl := StaticTTL(2*time.Minute, time.Hour, 30*time.Second)
	assert.Equal(t, 90*time.Second, ttl)
}

func TestStaticTTL_ExpiresInClamps(t *testing.T) {
	// static mode still clamps to expiresIn when expiresIn < timeout
	ttl := StaticTTL(time.Hour, 10*time.Second, time.Second)
	assert.Equal(t, 9*time.Second, ttl)
}

func TestDerivedTTL_ZeroInboundSkipped(t *testing.T) {
	// inboundRemaining=0 means "unknown/not set" — should not constrain
	ttl := DerivedTTL(10*time.Minute, 0, time.Hour, 30*time.Second)
	assert.Equal(t, 9*time.Minute+30*time.Second, ttl)
}
