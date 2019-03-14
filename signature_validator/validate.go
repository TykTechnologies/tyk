package signature_validator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

type Validator interface {
	Init(hasherName string) error
	Validate(attempt, actual string, allowedClockSkew int64) error
}

type SignatureValidator struct {
	h Hasher
}

func (v *SignatureValidator) Init(hasherName string) error {
	switch hasherName {
	case "MasherySha256":
		v.h = MasherySha256Sum{}
	case "MasheryMd5":
		v.h = MasheryMd5sum{}
	default:
		return errors.New(fmt.Sprintf("unsupported hasher type (%s)", hasherName))
	}

	return nil
}

func (v SignatureValidator) Validate(signatureAttempt, apiKey, sharedSecret string, allowedClockSkew int64) error {
	signatureAttemptHex, _ := hex.DecodeString(signatureAttempt)

	now := time.Now().Unix()
	for i := int64(0); i <= allowedClockSkew; i++ {
		if bytes.Equal(v.h.Hash(apiKey, sharedSecret, now+i), signatureAttemptHex) {
			return nil
		}

		if i == int64(0) {
			continue
		}

		if bytes.Equal(v.h.Hash(apiKey, sharedSecret, now-i), signatureAttemptHex) {
			return nil
		}
	}

	return errors.New("signature is not valid")
}
