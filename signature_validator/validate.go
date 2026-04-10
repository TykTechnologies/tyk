package signature_validator

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
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
	case "MasherySHA256":
		v.h = MasherySha256Sum{}
	case "MasheryMD5":
		v.h = MasheryMd5sum{}
	default:
		return errors.New(fmt.Sprintf("unsupported hasher type (%s)", hasherName))
	}

	return nil
}

func (v SignatureValidator) Validate(signature, key, secret string, allowedClockSkew int64) error {
	signatureBytes, _ := hex.DecodeString(signature)
	now := time.Now().Unix()
	for i := int64(0); i <= allowedClockSkew; i++ {
		if bytes.Equal(v.h.Hash(key, secret, now+i), signatureBytes) {
			return nil
		}

		if i == int64(0) {
			continue
		}

		if bytes.Equal(v.h.Hash(key, secret, now-i), signatureBytes) {
			return nil
		}
	}

	return errors.New("signature is not valid")
}
