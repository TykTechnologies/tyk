package signature_validator

import (
	"encoding/hex"
	"testing"
	"time"
)

// Verifies: STK-REQ-087, SYS-REQ-175, SW-REQ-162
// MCDC SYS-REQ-175: signature_validator_operation_terminal=T => TRUE
// MCDC SW-REQ-162: signature_validator_operation_terminal=T => TRUE
// STK-REQ-087:STK-REQ-087-AC-01:acceptance
// STK-REQ-087:error_handling:negative
// SYS-REQ-175:error_handling:negative
// SW-REQ-162:nominal:nominal
// SW-REQ-162:boundary:nominal
// SW-REQ-162:error_handling:nominal
// SW-REQ-162:error_handling:negative
// SW-REQ-162:encoding_safety:nominal
// SW-REQ-162:determinism:nominal
func TestSignatureValidatorReqProof(t *testing.T) {
	t.Run("stable hasher names and digests", func(t *testing.T) {
		tests := []struct {
			name       string
			hasher     Hasher
			wantName   string
			wantDigest string
		}{
			{
				name:       "sha256",
				hasher:     MasherySha256Sum{},
				wantName:   "MasherySHA256",
				wantDigest: "fce2e80253cd438b666341176f34bde499116b63719e2482dae6965518ffd316",
			},
			{
				name:       "md5",
				hasher:     MasheryMd5sum{},
				wantName:   "MasheryMD5",
				wantDigest: "eb7cc742c07c2ce0d71fa2d5a6f81a91",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := tt.hasher.Name(); got != tt.wantName {
					t.Fatalf("Name = %q, want %q", got, tt.wantName)
				}
				if got := hex.EncodeToString(tt.hasher.Hash(token, sharedSecret, now)); got != tt.wantDigest {
					t.Fatalf("Hash = %q, want %q", got, tt.wantDigest)
				}
			})
		}
	})

	t.Run("validator initialization", func(t *testing.T) {
		tests := []struct {
			name    string
			hasher  string
			wantErr bool
		}{
			{name: "sha256 hasher", hasher: "MasherySHA256"},
			{name: "md5 hasher", hasher: "MasheryMD5"},
			{name: "unsupported hasher", hasher: "SomeJunk", wantErr: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				validator := SignatureValidator{}
				err := validator.Init(tt.hasher)
				if tt.wantErr && err == nil {
					t.Fatal("Init returned nil error, want unsupported hasher error")
				}
				if !tt.wantErr && err != nil {
					t.Fatalf("Init returned error: %v", err)
				}
			})
		}
	})

	t.Run("signature validation classifications", func(t *testing.T) {
		allowedClockSkew := int64(100)
		currentTime := time.Now().Unix()
		tests := []struct {
			name      string
			signature string
			wantErr   bool
		}{
			{name: "missing signature", signature: "", wantErr: true},
			{name: "incorrect signature", signature: "abcde", wantErr: true},
			{name: "clock too slow", signature: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-500)), wantErr: true},
			{name: "clock too fast", signature: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+500)), wantErr: true},
			{name: "current timestamp", signature: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime))},
			{name: "future timestamp inside skew", signature: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+50))},
			{name: "past timestamp inside skew", signature: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-50))},
		}

		validator := SignatureValidator{}
		if err := validator.Init("MasherySHA256"); err != nil {
			t.Fatalf("Init returned error: %v", err)
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.signature, token, sharedSecret, allowedClockSkew)
				if tt.wantErr && err == nil {
					t.Fatal("Validate returned nil error, want invalid signature")
				}
				if !tt.wantErr && err != nil {
					t.Fatalf("Validate returned error: %v", err)
				}
			})
		}
	})
}
