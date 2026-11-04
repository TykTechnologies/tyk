package crypto

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	orgID := "test_org"
	keyID := "test_key"

	tests := []struct {
		name          string
		hashAlgorithm string
		expectedHash  string
		isLegacy      bool
		wantErr       bool
	}{
		{
			name:          "Valid algorithm - sha256",
			hashAlgorithm: HashSha256,
			expectedHash:  HashSha256,
			isLegacy:      false,
		},
		{
			name:          "Valid algorithm - murmur64",
			hashAlgorithm: HashMurmur64,
			expectedHash:  HashMurmur64,
			isLegacy:      false,
		},
		{
			name:          "Valid algorithm - murmur128",
			hashAlgorithm: HashMurmur128,
			expectedHash:  HashMurmur128,
			isLegacy:      false,
		},
		{
			name:          "Valid algorithm - murmur32",
			hashAlgorithm: HashMurmur32,
			expectedHash:  HashMurmur32,
			isLegacy:      false,
		},
		{
			name:          "Legacy behavior - empty string",
			hashAlgorithm: "",
			expectedHash:  "",
			isLegacy:      true,
		},
		{
			name:          "Invalid algorithm - falls back to murmur64",
			hashAlgorithm: "invalid_algo",
			expectedHash:  HashMurmur64,
			isLegacy:      false,
			wantErr:       true,
		},
		{
			name:          "Invalid algorithm - case sensitive (MURMUR64)",
			hashAlgorithm: "MURMUR64",
			expectedHash:  HashMurmur64,
			isLegacy:      false,
			wantErr:       true,
		},
		{
			name:          "Invalid algorithm - murmur3 (unknown)",
			hashAlgorithm: "murmur3",
			expectedHash:  HashMurmur64,
			isLegacy:      false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(orgID, keyID, tt.hashAlgorithm)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Unknown key hash function")
				assert.Contains(t, err.Error(), "Falling back to murmur64")
			} else {
				assert.NoError(t, err)
			}

			if tt.isLegacy {
				assert.Equal(t, orgID+keyID, token)
				assert.False(t, strings.HasPrefix(token, B64JSONPrefix))
			} else {
				assert.True(t, strings.HasPrefix(token, B64JSONPrefix))

				// Decode token
				jsonToken, err := base64.StdEncoding.DecodeString(token)
				require.NoError(t, err)

				parsedOrg, err := jsonparser.GetString(jsonToken, "org")
				require.NoError(t, err)
				assert.Equal(t, orgID, parsedOrg)

				parsedID, err := jsonparser.GetString(jsonToken, "id")
				require.NoError(t, err)
				assert.Equal(t, keyID, parsedID)

				parsedHash, err := jsonparser.GetString(jsonToken, "h")
				require.NoError(t, err)
				assert.Equal(t, tt.expectedHash, parsedHash)
			}
		})
	}
}

func TestTokenHashAlgo(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectedAlgo string
	}{
		{
			name:         "Legacy token",
			token:        "test_orgtest_key",
			expectedAlgo: "",
		},
		{
			name:         "Valid JSON token with murmur64",
			token:        base64.StdEncoding.EncodeToString([]byte(`{"org":"test_org","id":"test_key","h":"murmur64"}`)),
			expectedAlgo: "murmur64",
		},
		{
			name:         "Valid JSON token with sha256",
			token:        base64.StdEncoding.EncodeToString([]byte(`{"org":"test_org","id":"test_key","h":"sha256"}`)),
			expectedAlgo: "sha256",
		},
		{
			name:         "Invalid base64 token with prefix",
			token:        B64JSONPrefix + "invalid_base64",
			expectedAlgo: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo := TokenHashAlgo(tt.token)
			assert.Equal(t, tt.expectedAlgo, algo)
		})
	}
}
