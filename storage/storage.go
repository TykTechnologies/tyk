package storage

import (
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
	Connect() bool
	RateLimit
	KeyValue
	Redis
	Analytics
	Notify
}

type RateLimit interface {
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{})
}

type KeyValue interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetMultiKey([]string) ([]string, error)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(string, string, int64) error
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteAllKeys() bool
	DeleteRawKey(string) bool
	GetKeysAndValues() map[string]string
	GetKeysAndValuesWithFilter(string) map[string]string
	DeleteKeys([]string) bool
	Decrement(string)
	IncrememntWithExpire(string, int64) int64
	DeleteScanMatch(string) bool
	GetKeyPrefix() string
	Exists(string) (bool, error)
	GetKeyTTL(keyName string) (ttl int64, err error)
}

type Redis interface {
	AddToSet(string, string)
	GetSet(string) (map[string]string, error)
	AddToSortedSet(string, string, float64)
	RemoveFromSet(string, string)
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(string, string, string) error
	GetListRange(string, int64, int64) ([]string, error)
	RemoveFromList(string, string) error
	AppendToSet(string, string)
}

type Analytics interface {
	AppendToSetPipelined(string, [][]byte)
	GetAndDeleteSet(string) []interface{}
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
}

type Notify interface {
	// notifications
	Publish(channel, message string) error
	StartPubSubHandler(channel string, callback func(interface{})) error
}

type AnalyticsHandler interface {
	Connect() bool
	Analytics
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

// TODO: add checks
func TokenID(token string) (id string, err error) {
	jsonToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	return jsonparser.GetString(jsonToken, "id")
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

func HashStr(in string, withAlg ...string) string {
	var algo string
	if len(withAlg) > 0 && withAlg[0] != "" {
		algo = withAlg[0]
	} else {
		algo = TokenHashAlgo(in)
	}

	h, _ := hashFunction(algo)
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
