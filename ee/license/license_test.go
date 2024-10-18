package license

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestEnableDisableTestMode(t *testing.T) {
	EnableTestMode()
	assert.True(t, testMode)
	assert.NotNil(t, lic)

	DisableTestMode()
	assert.False(t, testMode)
	assert.Nil(t, lic)
}

func TestNewTestLicense(t *testing.T) {
	EnableTestMode()
	defer DisableTestMode()

	features := []string{"feature1", "feature2"}
	NewTestLicense(features)

	assert.NotNil(t, lic)
	assert.True(t, lic.Scopes["feature1"])
	assert.True(t, lic.Scopes["feature2"])
	assert.False(t, lic.Scopes["feature3"])
}

func createTestLicense(t *testing.T, features []string, expiration time.Time) (string, string) {
	// Generate a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"scope": strings.Join(features, ","),
		"exp":   expiration.Unix(),
		"nbf":   time.Now().Unix(),
	})

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	return signedToken, publicKeyPEM
}

func TestLoad(t *testing.T) {
	// Test loading in test mode
	EnableTestMode()
	assert.NoError(t, Load(""))
	assert.NotNil(t, lic)
	DisableTestMode()

	// Create a license content with real content
	licenseContent, publicKey := createTestLicense(t, []string{"feature1", "feature2"}, time.Now().Add(24*time.Hour))

	// Set the public key
	oldPublicKeyPEM := PublicKeyPEM
	PublicKeyPEM = publicKey
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Test loading with valid license
	assert.NoError(t, Load(licenseContent))
	assert.NotNil(t, lic)

	// Test loading with invalid public key
	PublicKeyPEM = "invalid"
	assert.Error(t, Load(licenseContent))

	// Test loading empty content
	assert.Error(t, Load(""))
}

func TestHasFeature(t *testing.T) {
	EnableTestMode()
	defer DisableTestMode()

	NewTestLicense([]string{"feature1", "feature2"})

	assert.True(t, HasFeature("feature1"))
	assert.True(t, HasFeature("feature2"))
	assert.False(t, HasFeature("feature3"))

	DisableTestMode()
	assert.False(t, HasFeature("feature1"))
}

func TestAddRemoveFeature(t *testing.T) {
	EnableTestMode()
	defer DisableTestMode()

	NewTestLicense([]string{"feature1"})

	AddFeature("feature2")
	assert.True(t, HasFeature("feature2"))

	RemoveFeature("feature1")
	assert.False(t, HasFeature("feature1"))

	DisableTestMode()
	AddFeature("feature3")
	assert.False(t, HasFeature("feature3"))
}

func TestLoadWithExpiredLicense(t *testing.T) {
	DisableTestMode()
	defer EnableTestMode()

	oldPublicKeyPEM := PublicKeyPEM
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Create an expired license
	licenseContent, publicKey := createTestLicense(t, []string{"feature1", "feature2"}, time.Now().Add(-1*time.Hour))

	// Set the public key
	PublicKeyPEM = publicKey

	// Try to load the expired license
	err := Load(licenseContent)
	assert.Error(t, err)
	assert.Equal(t, "failed to parse token: Token is expired", err.Error())
}

func TestLoadWithFutureLicense(t *testing.T) {
	DisableTestMode()
	defer EnableTestMode()

	oldPublicKeyPEM := PublicKeyPEM
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Use a fixed time for both license creation and validation
	fixedTime := time.Now()

	// Create a future license (24 hours in the future)
	licenseContent, publicKey := createTestLicense(t, []string{"feature1", "feature2"}, fixedTime.Add(24*time.Hour))

	// Set the public key
	PublicKeyPEM = publicKey

	// Mock time.Now() to return the fixed time
	oldTimeNow := timeNow
	timeNow = func() time.Time { return fixedTime }
	defer func() { timeNow = oldTimeNow }()

	// Try to load the future license
	err := Load(licenseContent)
	assert.Error(t, err)
	assert.Equal(t, "license not valid yet", err.Error())
}

func TestLoadWithInvalidSignature(t *testing.T) {
	DisableTestMode()
	defer EnableTestMode()

	oldPublicKeyPEM := PublicKeyPEM
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Create a valid license
	licenseContent, _ := createTestLicense(t, []string{"feature1", "feature2"}, time.Now().Add(1*time.Hour))

	// Generate a different key for verification
	differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Set the public key to the different key
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&differentKey.PublicKey)
	assert.NoError(t, err)
	PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	// Try to load the license with invalid signature
	err = Load(licenseContent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "crypto/rsa: verification error")
}

func TestLoadWithMissingClaims(t *testing.T) {
	DisableTestMode()
	defer EnableTestMode()

	oldPublicKeyPEM := PublicKeyPEM
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Generate a token with missing claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"scope": "feature1,feature2",
		// Missing "exp" and "nbf" claims
	})

	// Generate a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	// Set the public key
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	// Try to load the license with missing claims
	err = Load(signedToken)
	assert.Error(t, err)
	assert.Equal(t, "exp claim is missing or invalid", err.Error())
}

func TestLoadWithInvalidScope(t *testing.T) {
	DisableTestMode()
	defer EnableTestMode()

	oldPublicKeyPEM := PublicKeyPEM
	defer func() { PublicKeyPEM = oldPublicKeyPEM }()

	// Generate a token with invalid scope
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"nbf":   time.Now().Add(-1 * time.Hour).Unix(),
		"scope": 12345, // Invalid scope type
	})

	// Generate a private key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	// Set the public key
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}))

	// Try to load the license with invalid scope
	err = Load(signedToken)
	assert.Error(t, err)
	assert.Equal(t, "scope claim is missing or invalid", err.Error())
}
