package signature_validator

import (
	"encoding/hex"
	"testing"
	"time"
)

// Verifies: STK-REQ-087, SYS-REQ-175, SW-REQ-162
// STK-REQ-087:error_handling:negative
// SYS-REQ-175:error_handling:negative
// SW-REQ-162:nominal:nominal
// SW-REQ-162:boundary:nominal
// SW-REQ-162:error_handling:nominal
// SW-REQ-162:error_handling:negative
// SW-REQ-162:determinism:nominal
func TestValidateSignature_Init(t *testing.T) {
	type tt = struct {
		name    string
		in      string
		wantErr bool
	}

	suite := []tt{
		{name: "empty hasher", in: "", wantErr: true},
		{name: "unknown hasher", in: "SomeJunk", wantErr: true},
		{name: "sha256 hasher", in: "MasherySHA256"},
		{name: "md5 hasher", in: "MasheryMD5"},
	}

	for _, s := range suite {
		t.Run(s.name, func(t *testing.T) {
			validator := SignatureValidator{}
			err := validator.Init(s.in)

			if s.wantErr && err == nil {
				t.Fatal("expected error, got success")
			}
			if !s.wantErr && err != nil {
				t.Fatalf("expected success, got error %s", err.Error())
			}
		})
	}
}

// Verifies: STK-REQ-087, SYS-REQ-175, SW-REQ-162
// STK-REQ-087:error_handling:negative
// SYS-REQ-175:error_handling:negative
// SW-REQ-162:nominal:nominal
// SW-REQ-162:boundary:nominal
// SW-REQ-162:error_handling:nominal
// SW-REQ-162:error_handling:negative
// SW-REQ-162:encoding_safety:nominal
// SW-REQ-162:determinism:nominal
func TestValidateSignature_Validate(t *testing.T) {
	type tt struct {
		name             string
		SignatureAttempt string
		wantErr          bool
	}

	allowedClockSkew := int64(100)
	currentTime := time.Now().Unix()

	suite := []tt{
		{name: "missing signature", SignatureAttempt: "", wantErr: true},
		{name: "incorrect signature", SignatureAttempt: "abcde", wantErr: true},
		{name: "clock too slow", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-500)), wantErr: true},
		{name: "clock too fast", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+500)), wantErr: true},
		{name: "current timestamp", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime))},
		{name: "future timestamp inside skew", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+50))},
		{name: "past timestamp inside skew", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-50))},
	}

	validator := SignatureValidator{}
	_ = validator.Init("MasherySHA256")

	for _, s := range suite {
		t.Run(s.name, func(t *testing.T) {
			err := validator.Validate(s.SignatureAttempt, token, sharedSecret, allowedClockSkew)
			if s.wantErr && err == nil {
				t.Fatal("expected invalid signature")
			}
			if !s.wantErr && err != nil {
				t.Fatalf("expected valid signature, got error %s", err.Error())
			}
		})
	}
}
