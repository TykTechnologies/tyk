package upstreamoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/internal/crypto"
)

func TestGetToken_CacheHit(t *testing.T) {
	secret := "test-secret"
	cacheKey := "test-cache-key"
	extraMetadata := []string{"scope", "instance_url"}

	// Mock encrypted token data
	encryptedToken := crypto.Encrypt(crypto.GetPaddedString(secret), "cached-access-token")
	tokenData := TokenData{
		Token: encryptedToken,
		ExtraMetadata: map[string]interface{}{
			"scope":        "read write",
			"instance_url": "https://example.com",
		},
	}
	tokenDataBytes, err := json.Marshal(tokenData)
	require.NoError(t, err)

	// Setup mocks
	storage := &mockStorage{
		data: map[string]string{
			cacheKey: string(tokenDataBytes),
		},
	}
	storage.On("GetKey", cacheKey).Return(string(tokenDataBytes), nil)

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Mock obtain token function (should not be called)
	obtainTokenFunc := func(_ context.Context) (*oauth2.Token, error) {
		t.Fatal("obtainTokenFunc should not be called for cache hit")
		return nil, nil
	}

	// Execute
	token, err := getToken(req, cacheKey, obtainTokenFunc, secret, extraMetadata, storage)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "cached-access-token", token)

	// Verify metadata was set in context
	contextData := CtxGetData(req)
	assert.Equal(t, "read write", contextData["scope"])
	assert.Equal(t, "https://example.com", contextData["instance_url"])
}

func TestGetToken_CacheMiss(t *testing.T) {
	secret := "test-secret"
	cacheKey := "test-cache-key"
	extraMetadata := []string{"scope"}

	// Setup mocks
	storage := &mockStorage{data: make(map[string]string)}
	storage.On("GetKey", cacheKey).Return("", fmt.Errorf("not found"))
	storage.On("Lock", cacheKey+":lock", mock.AnythingOfType("time.Duration")).Return(true, nil)
	storage.On("SetKey", cacheKey, mock.AnythingOfType("string"), mock.AnythingOfType("int64")).Return(nil)

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Mock obtain token function
	newToken := &oauth2.Token{
		AccessToken: "new-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	newToken = newToken.WithExtra(map[string]interface{}{
		"scope": "read write admin",
	})

	obtainTokenFunc := func(_ context.Context) (*oauth2.Token, error) {
		return newToken, nil
	}

	// Execute
	token, err := getToken(req, cacheKey, obtainTokenFunc, secret, extraMetadata, storage)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", token)

	// Verify token was cached
	storage.AssertCalled(t, "SetKey", cacheKey, mock.AnythingOfType("string"), mock.AnythingOfType("int64"))

	// Verify metadata was set in context
	contextData := CtxGetData(req)
	assert.Equal(t, "read write admin", contextData["scope"])
}

func TestGetToken_ObtainTokenError(t *testing.T) {
	secret := "test-secret"
	cacheKey := "test-cache-key"

	// Setup mocks
	storage := &mockStorage{data: make(map[string]string)}
	storage.On("GetKey", cacheKey).Return("", fmt.Errorf("not found"))
	storage.On("Lock", cacheKey+":lock", mock.AnythingOfType("time.Duration")).Return(true, nil)

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Mock obtain token function that fails
	obtainTokenFunc := func(_ context.Context) (*oauth2.Token, error) {
		return nil, fmt.Errorf("OAuth server error")
	}

	// Execute
	token, err := getToken(req, cacheKey, obtainTokenFunc, secret, []string{}, storage)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth server error")
	assert.Empty(t, token)
}

func TestSetTokenInCache(t *testing.T) {
	storage := &mockStorage{data: make(map[string]string)}
	storage.On("SetKey", "test-key", "test-token", mock.AnythingOfType("int64")).Return(nil)

	cacheKey := "test-key"
	token := "test-token"
	ttl := time.Hour

	err := setTokenInCache(storage, cacheKey, token, ttl)

	assert.NoError(t, err)
	storage.AssertCalled(t, "SetKey", cacheKey, token, mock.AnythingOfType("int64"))
}

func TestCreateTokenDataBytes(t *testing.T) {
	encryptedToken := "encrypted-token"
	token := &oauth2.Token{
		AccessToken: "access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"scope":        "read write",
		"instance_url": "https://example.com",
		"empty_field":  "",
	})
	extraMetadataKeys := []string{"scope", "instance_url", "empty_field", "missing_field"}

	tokenDataBytes, err := CreateTokenDataBytes(encryptedToken, token, extraMetadataKeys)

	assert.NoError(t, err)
	assert.NotEmpty(t, tokenDataBytes)

	// Verify the structure
	var tokenData TokenData
	err = json.Unmarshal(tokenDataBytes, &tokenData)
	assert.NoError(t, err)
	assert.Equal(t, encryptedToken, tokenData.Token)
	assert.Equal(t, "read write", tokenData.ExtraMetadata["scope"])
	assert.Equal(t, "https://example.com", tokenData.ExtraMetadata["instance_url"])
	assert.NotContains(t, tokenData.ExtraMetadata, "empty_field")
	assert.NotContains(t, tokenData.ExtraMetadata, "missing_field")
}

func TestUnmarshalTokenData(t *testing.T) {
	originalData := TokenData{
		Token: "test-token",
		ExtraMetadata: map[string]interface{}{
			"scope": "read write",
			"url":   "https://example.com",
		},
	}

	tokenDataBytes, err := json.Marshal(originalData)
	require.NoError(t, err)

	result, err := UnmarshalTokenData(string(tokenDataBytes))

	assert.NoError(t, err)
	assert.Equal(t, originalData.Token, result.Token)
	assert.Equal(t, originalData.ExtraMetadata, result.ExtraMetadata)
}

func TestUnmarshalTokenData_InvalidJSON(t *testing.T) {
	invalidJSON := "invalid json"

	result, err := UnmarshalTokenData(invalidJSON)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal token data")
	assert.Equal(t, TokenData{}, result)
}

func TestBuildMetadataMap(t *testing.T) {
	token := &oauth2.Token{
		AccessToken: "access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	token = token.WithExtra(map[string]interface{}{
		"scope":        "read write",
		"instance_url": "https://example.com",
		"empty_field":  "",
		"nil_field":    nil,
		"number_field": 123,
	})

	extraMetadataKeys := []string{"scope", "instance_url", "empty_field", "nil_field", "number_field", "missing_field"}

	result := BuildMetadataMap(token, extraMetadataKeys)

	assert.Equal(t, "read write", result["scope"])
	assert.Equal(t, "https://example.com", result["instance_url"])
	assert.Equal(t, 123, result["number_field"])
	assert.NotContains(t, result, "empty_field")
	assert.NotContains(t, result, "nil_field")
	assert.NotContains(t, result, "missing_field")
}

func TestRetryGetKeyAndLock_Success(t *testing.T) {
	cacheKey := "test-key"
	storage := &mockStorage{
		data: map[string]string{
			cacheKey: "cached-data",
		},
	}
	storage.On("GetKey", cacheKey).Return("cached-data", nil)

	result, err := retryGetKeyAndLock(cacheKey, storage)

	assert.NoError(t, err)
	assert.Equal(t, "cached-data", result)
}

func TestRetryGetKeyAndLock_LockAcquired(t *testing.T) {
	cacheKey := "test-key"
	lockKey := cacheKey + ":lock"

	storage := &mockStorage{data: make(map[string]string)}
	storage.On("GetKey", cacheKey).Return("", fmt.Errorf("not found"))
	storage.On("Lock", lockKey, mock.AnythingOfType("time.Duration")).Return(true, nil)

	result, err := retryGetKeyAndLock(cacheKey, storage)

	assert.NoError(t, err)
	assert.Empty(t, result)
	storage.AssertCalled(t, "Lock", lockKey, 5*time.Second)
}

func TestRetryGetKeyAndLock_MaxRetriesExceeded(t *testing.T) {
	cacheKey := "test-key"
	lockKey := cacheKey + ":lock"

	storage := &mockStorage{data: make(map[string]string)}
	storage.On("GetKey", cacheKey).Return("", fmt.Errorf("not found"))
	storage.On("Lock", lockKey, mock.AnythingOfType("time.Duration")).Return(false, fmt.Errorf("lock failed"))

	result, err := retryGetKeyAndLock(cacheKey, storage)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire lock after retries")
	assert.Empty(t, result)
}

func TestSetExtraMetadata(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	keyList := []string{"scope", "instance_url", "missing_key"}
	metadata := map[string]interface{}{
		"scope":        "read write",
		"instance_url": "https://example.com",
		"empty_field":  "",
	}

	SetExtraMetadata(req, keyList, metadata)

	contextData := CtxGetData(req)
	assert.Equal(t, "read write", contextData["scope"])
	assert.Equal(t, "https://example.com", contextData["instance_url"])
	assert.NotContains(t, contextData, "missing_key")
	assert.NotContains(t, contextData, "empty_field")
}

func TestSetExtraMetadata_ExistingContext(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Set some initial context data
	initialData := map[string]interface{}{
		"existing_key": "existing_value",
	}
	CtxSetData(req, initialData)

	keyList := []string{"scope"}
	metadata := map[string]interface{}{
		"scope": "read write",
	}

	SetExtraMetadata(req, keyList, metadata)

	contextData := CtxGetData(req)
	assert.Equal(t, "existing_value", contextData["existing_key"])
	assert.Equal(t, "read write", contextData["scope"])
}
