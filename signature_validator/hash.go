package signature_validator

import (
	"crypto/md5"
	"crypto/sha256"
	"strconv"
)

type Hasher interface {
	Name() string
	Hash(token string, sharedSecret string, timeStamp int64) []byte
}

type MasherySha256Sum struct{}

func (m MasherySha256Sum) Name() string {
	return "MasherySHA256"
}

func (m MasherySha256Sum) Hash(token string, sharedSecret string, timeStamp int64) []byte {
	signature := sha256.Sum256([]byte(token + sharedSecret + strconv.FormatInt(timeStamp, 10)))

	return signature[:]
}

type MasheryMd5sum struct{}

func (m MasheryMd5sum) Name() string {
	return "MasheryMD5"
}

func (m MasheryMd5sum) Hash(token string, sharedSecret string, timeStamp int64) []byte {
	signature := md5.Sum([]byte(token + sharedSecret + strconv.FormatInt(timeStamp, 10)))

	return signature[:]
}
