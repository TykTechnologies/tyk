package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionCache(t *testing.T) {
	// Create a new session cache
	cache := NewSessionCache()

	// Test data
	testData := SessionState{
		OrgID: "Tyk",
	}

	// Test key
	testKey := "testKey"

	// Test Set method
	cache.Set(testKey, testData, 0)

	// Test Get method
	retrievedData, ok := cache.Get(testKey)

	assert.True(t, ok)
	assert.Equal(t, retrievedData.OrgID, testData.OrgID)

	// Test non-existent key
	nonExistentKey := "nonExistentKey"
	retrievedData, ok = cache.Get(nonExistentKey)

	assert.Nil(t, retrievedData)
	assert.False(t, ok)
}
