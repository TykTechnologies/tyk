package signature_validator

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
)

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

		validator := SignatureValidator{}
		err := validator.Init(s.In)

		if err != nil && s.Error == nil {
			t.Errorf("expected success, got error %s", err.Error())
			t.FailNow()
		}

		if err == nil && s.Error != nil {
			t.Errorf("expected error (%s), got success", s.Error.Error())
			t.FailNow()
		}
	}
}

func TestValidateSignature_Validate(t *testing.T) {
	test.Flaky(t) // TODO: TT-5264

	type tt struct {
		SignatureAttempt string
		Error            error
	}

	allowedClockSkew := int64(100)

	suite := []tt{
		{SignatureAttempt: "", Error: errors.New("should not pass with missing signature")},
		{SignatureAttempt: "abcde", Error: errors.New("should not pass with incorrect signature")},
		{SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, time.Now().Unix()-101)), Error: errors.New("clock too slow")},
		{SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, time.Now().Unix()+101)), Error: errors.New("clock too fast")},
		{SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, time.Now().Unix())), Error: nil},
		{SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, time.Now().Unix()+99)), Error: nil},
		{SignatureAttempt: hex.EncodeToString(MasherySha256Sum{}.Hash(token, sharedSecret, time.Now().Unix()-99)), Error: nil},
	}

	validator := SignatureValidator{}
	_ = validator.Init("MasherySHA256")

	for _, s := range suite {
		err := validator.Validate(s.SignatureAttempt, token, sharedSecret, allowedClockSkew)
		if err != nil && s.Error == nil {
			t.Errorf("expected valid, got error %s", err.Error())
			t.FailNow()
		}

		if err == nil && s.Error != nil {
			t.Errorf("expected error (%s), got valid", s.Error.Error())
			t.FailNow()
		}
	}
}
