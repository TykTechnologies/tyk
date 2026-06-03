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

// TestParseUnverifiedClaims_IgnoresSignature pins the documented
// security model: ParseUnverifiedClaims must succeed regardless of
// signature validity. Token authentication is the upstream JWT /
// introspection middleware's responsibility — this helper only reads
// claim fields and must not couple to a verifier or a key. If a future
// "fix" adds signature verification here, this test fails and the
// reviewer is forced to revisit the godoc and the won't-fix rationale.
func TestParseUnverifiedClaims_IgnoresSignature(t *testing.T) {
	t.Run("token signed with arbitrary secret parses fine", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "alice"})
		signed, err := tok.SignedString([]byte("some-secret-the-gateway-does-not-know"))
		require.NoError(t, err)

		claims, err := ParseUnverifiedClaims(signed)
		require.NoError(t, err)
		assert.Equal(t, "alice", StringClaim(claims, "sub"))
	})

	t.Run("token with a tampered signature still parses", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "bob"})
		signed, err := tok.SignedString([]byte("k"))
		require.NoError(t, err)
		tampered := signed[:len(signed)-4] + "AAAA"

		claims, err := ParseUnverifiedClaims(tampered)
		require.NoError(t, err)
		assert.Equal(t, "bob", StringClaim(claims, "sub"))
	})

	t.Run("alg=none token parses (verifier elsewhere is responsible for rejecting it)", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "carol"})
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		claims, err := ParseUnverifiedClaims(signed)
		require.NoError(t, err)
		assert.Equal(t, "carol", StringClaim(claims, "sub"))
	})
}
