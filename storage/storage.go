package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/buger/jsonparser"
	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/murmur3"
	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

// ErrKeyNotFound is a standard error for when a key is not found in the storage engine
var ErrKeyNotFound = errors.New("key not found")

// Handler is a standard interface to a storage backend, used by
// AuthorisationManager to read and write key values to the backend
type Handler interface {
	GetKey(context.Context, string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetMultiKey(context.Context, []string) ([]string, error)
	GetRawKey(context.Context, string) (string, error)
	SetKey(context.Context, string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(context.Context, string, string, int64) error
	SetExp(context.Context, string, int64) error   // Set key expiration
	GetExp(context.Context, string) (int64, error) // Returns expiry of a key
	GetKeys(context.Context, string) []string
	DeleteKey(context.Context, string) bool
	DeleteAllKeys(context.Context) bool
	DeleteRawKey(context.Context, string) bool
	Connect(context.Context) bool
	GetKeysAndValues(context.Context) map[string]string
	GetKeysAndValuesWithFilter(context.Context, string) map[string]string
	DeleteKeys(context.Context, []string) bool
	Decrement(context.Context, string)
	IncrememntWithExpire(context.Context, string, int64) int64
	SetRollingWindow(ctx context.Context, key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(ctx context.Context, key string, per int64, pipeline bool) (int, []interface{})
	GetSet(context.Context, string) (map[string]string, error)
	AddToSet(context.Context, string, string)
	GetAndDeleteSet(context.Context, string) []interface{}
	RemoveFromSet(context.Context, string, string)
	DeleteScanMatch(context.Context, string) bool
	GetKeyPrefix(context.Context) string
	AddToSortedSet(context.Context, string, string, float64)
	GetSortedSetRange(context.Context, string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(context.Context, string, string, string) error
	GetListRange(context.Context, string, int64, int64) ([]string, error)
	RemoveFromList(context.Context, string, string) error
	AppendToSet(context.Context, string, string)
	Exists(context.Context, string) (bool, error)
}

type AnalyticsHandler interface {
	Connect(context.Context) bool
	AppendToSetPipelined(context.Context, string, [][]byte)
	GetAndDeleteSet(context.Context, string) []interface{}
	SetExp(context.Context, string, int64) error   // Set key expiration
	GetExp(context.Context, string) (int64, error) // Returns expiry of a key
}

const defaultHashAlgorithm = "murmur64"

// If hashing algorithm is empty, use legacy key generation
func GenerateToken(orgID, keyID, hashAlgorithm string) (string, error) {
	if keyID == "" {
		keyID = strings.Replace(uuid.NewV4().String(), "-", "", -1)
	}

	if hashAlgorithm != "" {
		_, err := hashFunction(hashAlgorithm)
		if err != nil {
			hashAlgorithm = defaultHashAlgorithm
		}

		jsonToken := fmt.Sprintf(`{"org":"%s","id":"%s","h":"%s"}`, orgID, keyID, hashAlgorithm)
		return base64.StdEncoding.EncodeToString([]byte(jsonToken)), err
	}

	// Legacy keys
	return orgID + keyID, nil
}

// `{"` in base64
const B64JSONPrefix = "ey"

func TokenHashAlgo(token string) string {
	// Legacy tokens not b64 and not JSON records
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			hashAlgo, _ := jsonparser.GetString(jsonToken, "h")
			return hashAlgo
		}
	}

	return ""
}

func TokenOrg(token string) string {
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			// Checking error in case if it is a legacy tooken which just by accided has the same b64JSON prefix
			if org, err := jsonparser.GetString(jsonToken, "org"); err == nil {
				return org
			}
		}
	}

	// 24 is mongo bson id length
	if len(token) > 24 {
		return token[:24]
	}

	return ""
}

var (
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

func HashStr(in string) string {
	h, _ := hashFunction(TokenHashAlgo(in))
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

func HashKey(in string) string {
	if !config.Global().HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}
