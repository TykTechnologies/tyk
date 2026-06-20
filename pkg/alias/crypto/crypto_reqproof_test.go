package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	internalcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	aliascrypto "github.com/TykTechnologies/tyk/pkg/alias/crypto"
)

// Verifies: STK-REQ-041, SYS-REQ-129, SW-REQ-116
// SW-REQ-116:nominal:nominal
// SW-REQ-116:boundary:nominal
// SW-REQ-116:determinism:nominal
func TestAliasCryptoHashStrMatchesInternalHelper(t *testing.T) {
	tests := []struct {
		name  string
		input string
		algo  []string
	}{
		{name: "default algorithm", input: "alias-key"},
		{name: "explicit sha256", input: "alias-key", algo: []string{internalcrypto.HashSha256}},
		{name: "unknown algorithm fallback", input: "alias-key", algo: []string{"unknown"}},
		{name: "empty input", input: "", algo: []string{internalcrypto.HashMurmur32}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, internalcrypto.HashStr(tt.input, tt.algo...), aliascrypto.HashStr(tt.input, tt.algo...))
		})
	}
}
