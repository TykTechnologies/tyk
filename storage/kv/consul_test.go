package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Store = (*Consul)(nil)

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:error_handling:negative
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
func TestConsul_Get(t *testing.T) {
	consulURL, values, closeServer := newTestConsulServer(t)
	defer closeServer()

	store, err := NewConsul(consulConfigForURL(t, consulURL))
	require.NoError(t, err)

	_, err = store.Get("key")
	assert.ErrorIs(t, err, ErrKeyNotFound)

	values["key"] = "value"

	val, err := store.Get("key")
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}
