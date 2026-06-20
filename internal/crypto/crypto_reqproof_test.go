package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-041, SYS-REQ-129, SW-REQ-116
// MCDC SYS-REQ-129: crypto_helper_operation_terminal=T => TRUE
// SW-REQ-116:nominal:nominal
// SW-REQ-116:boundary:nominal
// SW-REQ-116:determinism:nominal
//
//mcdc:ignore SYS-REQ-129: crypto_helper_operation_terminal=F => FALSE -- the onboarded crypto helper operations are synchronous local helpers that either return mapped data, parsed token fields, generated artifacts, explicit empty/error outcomes, or deterministic in-memory certificate-pool updates before returning; a non-terminal result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestCryptoHelpersPreserveLocalBehavior(t *testing.T) {
	t.Run("hash key returns raw or hashed value", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			hashKey bool
			want    string
		}{
			{name: "hash disabled", input: "raw-key", hashKey: false, want: "raw-key"},
			{name: "hash enabled uses token algorithm fallback", input: "raw-key", hashKey: true, want: HashStr("raw-key")},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, HashKey(tt.input, tt.hashKey))
			})
		}
	})

	t.Run("explicit hash algorithm selection", func(t *testing.T) {
		sum := sha256.Sum256([]byte("abc"))
		tests := []struct {
			name  string
			algo  string
			input string
			want  string
		}{
			{name: "sha256", algo: HashSha256, input: "abc", want: hex.EncodeToString(sum[:])},
			{name: "default murmur32 for empty algorithm", algo: "", input: "abc", want: HashStr("abc", HashMurmur32)},
			{name: "unknown algorithm falls back to murmur32", algo: "unknown", input: "abc", want: HashStr("abc", HashMurmur32)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, HashStr(tt.input, tt.algo))
			})
		}
	})

	t.Run("token generation and parsing", func(t *testing.T) {
		tests := []struct {
			name        string
			orgID       string
			keyID       string
			algo        string
			wantToken   string
			wantOrg     string
			wantID      string
			wantAlgo    string
			wantErr     bool
			wantEncoded bool
		}{
			{
				name:      "legacy token concatenates org and key",
				orgID:     "507f1f77bcf86cd799439011",
				keyID:     "legacy-key",
				wantToken: "507f1f77bcf86cd799439011legacy-key",
				wantOrg:   "507f1f77bcf86cd799439011",
			},
			{
				name:        "encoded token preserves requested algorithm",
				orgID:       "org-1",
				keyID:       "key-1",
				algo:        HashMurmur64,
				wantOrg:     "org-1",
				wantID:      "key-1",
				wantAlgo:    HashMurmur64,
				wantEncoded: true,
			},
			{
				name:        "unknown algorithm falls back to default",
				orgID:       "org-2",
				keyID:       "key-2",
				algo:        "unknown",
				wantOrg:     "org-2",
				wantID:      "key-2",
				wantAlgo:    DefaultHashAlgorithm,
				wantErr:     true,
				wantEncoded: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token, err := GenerateToken(tt.orgID, tt.keyID, tt.algo)
				if tt.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}

				if tt.wantToken != "" {
					assert.Equal(t, tt.wantToken, token)
				}
				if tt.wantEncoded {
					assert.True(t, strings.HasPrefix(token, B64JSONPrefix))
					id, err := TokenID(token)
					require.NoError(t, err)
					assert.Equal(t, tt.wantID, id)
				}
				assert.Equal(t, tt.wantOrg, TokenOrg(token))
				assert.Equal(t, tt.wantAlgo, TokenHashAlgo(token))
			})
		}
	})

	t.Run("token parsing reports malformed inputs", func(t *testing.T) {
		tests := []struct {
			name      string
			token     string
			wantOrg   string
			wantIDErr bool
		}{
			{name: "non base64 token has no id", token: "not-base64", wantIDErr: true},
			{name: "short legacy token has no org", token: "short", wantIDErr: true},
			{name: "base64 json without org falls back to empty org", token: base64.StdEncoding.EncodeToString([]byte(`{"id":"key"}`)), wantIDErr: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := TokenID(tt.token)
				assert.Equal(t, tt.wantIDErr, err != nil)
				assert.Equal(t, tt.wantOrg, TokenOrg(tt.token))
			})
		}
	})
}

// Verifies: SYS-REQ-129, SW-REQ-116
// STK-REQ-041:error_handling:negative
// SW-REQ-116:error_handling:negative
func TestCryptoEncryptionHelpersReturnLocalOutcomes(t *testing.T) {
	t.Run("encrypt decrypt round trip", func(t *testing.T) {
		tests := []struct {
			name      string
			plaintext string
		}{
			{name: "empty plaintext", plaintext: ""},
			{name: "non empty plaintext", plaintext: "gateway secret"},
		}

		key := GetPaddedString("secret")
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ciphertext := Encrypt(key, tt.plaintext)
				require.NotEmpty(t, ciphertext)
				assert.Equal(t, tt.plaintext, Decrypt(key, ciphertext))
			})
		}
	})

	t.Run("invalid inputs return empty string", func(t *testing.T) {
		tests := []struct {
			name string
			run  func() string
		}{
			{name: "encrypt with invalid key length", run: func() string { return Encrypt([]byte("short"), "value") }},
			{name: "decrypt with invalid base64", run: func() string { return Decrypt(GetPaddedString("secret"), "not base64") }},
			{name: "decrypt with short ciphertext", run: func() string {
				return Decrypt(GetPaddedString("secret"), base64.URLEncoding.EncodeToString([]byte("short")))
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Empty(t, tt.run())
			})
		}
	})
}
