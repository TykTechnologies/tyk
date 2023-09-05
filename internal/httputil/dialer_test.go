package httputil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDialer(t *testing.T) {
	want := time.Duration(0)
	dialer := NewDialer(time.Duration(0))

	assert.NotNil(t, dialer)
	assert.Equal(t, want, dialer.Timeout)
	assert.Equal(t, want, dialer.KeepAlive)

	want = 3 * time.Second
	dialer = NewDialer(3 * time.Second)

	assert.NotNil(t, dialer)
	assert.Equal(t, want, dialer.Timeout)
	assert.Equal(t, want, dialer.KeepAlive)
}
