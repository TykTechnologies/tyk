package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/murmur3"
)

const (
	HashSha256    = "sha256"
	HashMurmur32  = "murmur32"
	HashMurmur64  = "murmur64"
	HashMurmur128 = "murmur128"
)

func hashFunction(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case HashSha256:
		return sha256.New(), nil
	case HashMurmur64:
		return murmur3.New64(), nil
	case HashMurmur128:
		return murmur3.New128(), nil
	case "", HashMurmur32:
		return murmur3.New32(), nil
	default:
		return murmur3.New32(), fmt.Errorf("Unknown key hash function: %s. Falling back to murmur32.", algorithm)
	}
}

func HashStr(in string, withAlg ...string) string {
	var algo string
	if len(withAlg) > 0 && withAlg[0] != "" {
		algo = withAlg[0]
	} else {
		algo = TokenHashAlgo(in)
	}

	h, err := hashFunction(algo)

	if err != nil {
		logrus.Error(err)
	}

	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

func HashKey(in string, hashKey bool) string {
	if !hashKey {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}
