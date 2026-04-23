package crypto

import (
	"testing"

	"github.com/TykTechnologies/murmur3"
	"github.com/stretchr/testify/assert"
)

func TestHashFunction(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     string
		expectedHash  string
		expectedError string
	}{
		{
			name:          "Valid algorithm - sha256",
			algorithm:     HashSha256,
			expectedHash:  "sha256",
			expectedError: "",
		},
		{
			name:          "Valid algorithm - murmur64",
			algorithm:     HashMurmur64,
			expectedHash:  "murmur64",
			expectedError: "",
		},
		{
			name:          "Valid algorithm - murmur128",
			algorithm:     HashMurmur128,
			expectedHash:  "murmur128",
			expectedError: "",
		},
		{
			name:          "Valid algorithm - murmur32",
			algorithm:     HashMurmur32,
			expectedHash:  "murmur32",
			expectedError: "",
		},
		{
			name:          "Legacy behavior - empty string falls back to murmur32",
			algorithm:     "",
			expectedHash:  "murmur32",
			expectedError: "",
		},
		{
			name:          "Invalid algorithm - falls back to murmur64",
			algorithm:     "invalid_algo",
			expectedHash:  "murmur64",
			expectedError: "Unknown key hash function: invalid_algo. Falling back to murmur64.",
		},
		{
			name:          "Invalid algorithm - case sensitive (MURMUR64)",
			algorithm:     "MURMUR64",
			expectedHash:  "murmur64",
			expectedError: "Unknown key hash function: MURMUR64. Falling back to murmur64.",
		},
		{
			name:          "Invalid algorithm - murmur3 (unknown)",
			algorithm:     "murmur3",
			expectedHash:  "murmur64",
			expectedError: "Unknown key hash function: murmur3. Falling back to murmur64.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hashFunction(tt.algorithm)

			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify the type of hash returned
			switch tt.expectedHash {
			case "sha256":
				assert.Equal(t, 32, h.Size())
			case "murmur64":
				assert.IsType(t, murmur3.New64(), h)
			case "murmur128":
				assert.IsType(t, murmur3.New128(), h)
			case "murmur32":
				assert.IsType(t, murmur3.New32(), h)
			}
		})
	}
}

func TestHashStr(t *testing.T) {
	// Test that HashStr correctly uses the fallback algorithm
	input := "test_string"

	// Hash with explicit invalid algorithm
	hashWithInvalid := HashStr(input, "invalid_algo")

	// Hash with explicit murmur64
	hashWithMurmur64 := HashStr(input, HashMurmur64)

	// They should be equal since invalid falls back to murmur64
	assert.Equal(t, hashWithMurmur64, hashWithInvalid)

	// Test legacy behavior
	hashWithEmpty := HashStr(input, "")
	hashWithMurmur32 := HashStr(input, HashMurmur32)
	assert.Equal(t, hashWithMurmur32, hashWithEmpty)
}
