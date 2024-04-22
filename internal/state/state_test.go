package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEngine tests the basic functionality of the Engine struct.
func TestEngine(t *testing.T) {
	engine := New()

	// Test setting a value with no listeners should return ErrNoListeners
	err := engine.Set("key1", "ok")
	assert.Equal(t, ErrNoListeners, err, "Expected ErrNoListeners error when no listeners are set")

	// Set up a variable to capture listener output
	var receivedKey, receivedPrev, receivedCurrent string
	listener := func(key, previous, current string) {
		receivedKey = key
		receivedPrev = previous
		receivedCurrent = current
	}

	// Add listener to the engine
	engine.AddListener(listener)

	// Test setting a new value should trigger the listener
	err = engine.Set("key1", "warning")
	assert.Nil(t, err, "Expected no error when setting a new value with listeners present")
	assert.Equal(t, "key1", receivedKey, "Expected key to match the set key")
	assert.Equal(t, "warning", receivedPrev, "Expected previous value to match new value for a new key")
	assert.Equal(t, "warning", receivedCurrent, "Expected current value to match the set value")

	// Test updating the same key with the same value should not trigger the listener
	receivedKey = ""
	receivedPrev = ""
	receivedCurrent = ""
	err = engine.Set("key1", "warning")
	assert.Nil(t, err, "Expected no error when setting the same value")
	assert.Equal(t, "", receivedKey, "Expected no listener call when value does not change")

	// Test updating the same key with a new value should trigger the listener again
	err = engine.Set("key1", "blocked")
	assert.Nil(t, err, "Expected no error when updating with a new value")
	assert.Equal(t, "key1", receivedKey, "Expected key to match the set key")
	assert.Equal(t, "warning", receivedPrev, "Expected previous value to be the last set value")
	assert.Equal(t, "blocked", receivedCurrent, "Expected current value to match the new set value")
}
