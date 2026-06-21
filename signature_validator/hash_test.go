package signature_validator

import (
	"encoding/hex"
	"testing"
	"time"
)

const (
	token        = "5bcef48a3f03d311ff27d156630baf849e3b438b8a48fec99239d5c9"
	sharedSecret = "foobar"
	now          = 1546259837
)

// Verifies: STK-REQ-087, SYS-REQ-175, SW-REQ-162
// STK-REQ-087:STK-REQ-087-AC-01:acceptance
// SW-REQ-162:nominal:nominal
// SW-REQ-162:boundary:nominal
// SW-REQ-162:encoding_safety:nominal
// SW-REQ-162:determinism:nominal
func TestMasheryHashers(t *testing.T) {
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
				t.Fatalf("expected %s name, got %s", tt.wantName, got)
			}

			hashed := hex.EncodeToString(tt.hasher.Hash(token, sharedSecret, now))
			if hashed != tt.wantDigest {
				t.Fatalf("expected %s, got %s", tt.wantDigest, hashed)
			}
		})
	}
}

func BenchmarkMasherySha256Sum_Hash(b *testing.B) {

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		hasher := MasherySha256Sum{}
		hasher.Hash(token, sharedSecret, time.Now().Unix())
	}
}
