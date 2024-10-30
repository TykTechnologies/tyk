package httpctx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/stretchr/testify/assert"
)

func TestValue_SetAndGet(t *testing.T) {
	// Define a key and instantiate a new Value with type map[string]any
	key := "testKey"
	value := httpctx.NewValue[map[string]any](key)

	// Prepare a map to store in context
	expectedData := map[string]any{
		"userID":   123,
		"userRole": "admin",
	}

	// Create a new HTTP request using httptest
	req := httptest.NewRequest("GET", "/", nil)

	// Set the value in the request's context
	req = value.Set(req, expectedData)

	// Retrieve the value from the context
	retrievedData, ok := value.Get(req)
	assert.True(t, ok, "Expected to retrieve data from context, but got none")
	assert.Equal(t, expectedData, retrievedData, "Retrieved data does not match expected data")
}

func TestValue_GetWithMissingKey(t *testing.T) {
	// Define a key and instantiate a new Value with type map[string]any
	key := "missingKey"
	value := httpctx.NewValue[map[string]any](key)

	// Create a new HTTP request using httptest
	req := httptest.NewRequest("GET", "/", nil)

	// Try to retrieve the value from the context
	retrievedData, ok := value.Get(req)

	// Expect not to find any data
	assert.False(t, ok, "Expected no data in context, but some data was found")
	assert.Nil(t, retrievedData, "Expected retrieved data to be nil for a missing key")
}

func TestValue_SetDifferentTypes(t *testing.T) {
	// Test using a different type for Value, e.g., int
	intKey := "intKey"
	intValue := httpctx.NewValue[int](intKey)

	// Create a new HTTP request using httptest
	req := httptest.NewRequest("GET", "/", nil)

	// Set an int value in the context
	expectedInt := 42
	req = intValue.Set(req, expectedInt)

	// Retrieve the int value from the context
	retrievedInt, ok := intValue.Get(req)
	assert.True(t, ok, "Expected to retrieve int data from context, but got none")
	assert.Equal(t, expectedInt, retrievedInt, "Retrieved int value does not match expected value")
}
