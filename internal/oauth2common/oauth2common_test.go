package oauth2common

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringClaim_NilSafe(t *testing.T) {
	assert.Equal(t, "", StringClaim(nil, "azp"))
	assert.Equal(t, "", StringClaim(jwt.MapClaims{}, "azp"))
	assert.Equal(t, "client-1", StringClaim(jwt.MapClaims{"azp": "client-1"}, "azp"))
}

func TestStringClaim_WrongType(t *testing.T) {
	// Non-string claims must return "" rather than a stringified form.
	assert.Equal(t, "", StringClaim(jwt.MapClaims{"azp": 42}, "azp"))
	assert.Equal(t, "", StringClaim(jwt.MapClaims{"azp": []string{"x"}}, "azp"))
	assert.Equal(t, "", StringClaim(jwt.MapClaims{"azp": nil}, "azp"))
}

func TestStringFromAny(t *testing.T) {
	assert.Equal(t, "", StringFromAny(nil))
	assert.Equal(t, "", StringFromAny(42))
	assert.Equal(t, "hello", StringFromAny("hello"))
}

func TestParseUnverifiedClaims_RoundTrip(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user-1",
		"scope": "read write",
		"azp":   "client-1",
	})
	signed, err := tok.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	claims, err := ParseUnverifiedClaims(signed)
	require.NoError(t, err)
	assert.Equal(t, "user-1", StringClaim(claims, "sub"))
	assert.Equal(t, "read write", StringClaim(claims, "scope"))
	assert.Equal(t, "client-1", StringClaim(claims, "azp"))
}

func TestParseUnverifiedClaims_RejectsMalformed(t *testing.T) {
	_, err := ParseUnverifiedClaims("not-a-jwt")
	require.Error(t, err)
}
