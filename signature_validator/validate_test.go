package signature_validator

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

var _ Validator = (*SignatureValidator)(nil)

// Verifies: STK-REQ-041, SYS-REQ-129, SW-REQ-122
// SW-REQ-122:nominal:nominal
// SW-REQ-122:error_handling:nominal
// SW-REQ-122:error_handling:negative
func TestValidateSignature_Init(t *testing.T) {

	type tt = struct {
		In    string
		Error error
	}

	suite := []tt{
		{"", errors.New("empty string in init")},
		{"SomeJunk", errors.New("non existent")},
		{"MasherySHA256", nil},
		{"MasheryMD5", nil},
	}

	for _, s := range suite {
		t.Run(s.In, func(t *testing.T) {
			validator := SignatureValidator{}
			err := validator.Init(s.In)

			if err != nil && s.Error == nil {
				t.Fatalf("expected success, got error %s", err.Error())
			}

			if err == nil && s.Error != nil {
				t.Fatalf("expected error (%s), got success", s.Error.Error())
			}
		})
	}
}

// Verifies: STK-REQ-041, SYS-REQ-129, SW-REQ-122
// SW-REQ-122:nominal:nominal
// SW-REQ-122:boundary:nominal
// SW-REQ-122:error_handling:nominal
// SW-REQ-122:error_handling:negative
func TestValidateSignature_Validate(t *testing.T) {
	type tt struct {
		Name             string
		SignatureAttempt string
		Error            error
	}

	allowedClockSkew := int64(100)
	outsideClockSkew := allowedClockSkew * 2
	currentTime := time.Now().Unix()

	suite := []tt{
		{Name: "missing signature", SignatureAttempt: "", Error: errors.New("should not pass with missing signature")},
		{Name: "incorrect signature", SignatureAttempt: "abcde", Error: errors.New("should not pass with incorrect signature")},
		{Name: "clock too slow", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-outsideClockSkew)), Error: errors.New("clock too slow")},
		{Name: "clock too fast", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+outsideClockSkew)), Error: errors.New("clock too fast")},
		{Name: "current timestamp", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime)), Error: nil},
		{Name: "future timestamp inside skew", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime+allowedClockSkew-1)), Error: nil},
		{Name: "past timestamp inside skew", SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, currentTime-allowedClockSkew+1)), Error: nil},
	}

	validator := SignatureValidator{}
	_ = validator.Init("MasherySHA256")

	for _, s := range suite {
		t.Run(s.Name, func(t *testing.T) {
			err := validator.Validate(s.SignatureAttempt, token, sharedSecret, allowedClockSkew)
			if err != nil && s.Error == nil {
				t.Fatalf("expected valid, got error %s", err.Error())
			}

			if err == nil && s.Error != nil {
				t.Fatalf("expected error (%s), got valid", s.Error.Error())
			}
		})
	}
}
