package storage

import (
	"encoding/hex"
	"errors"

	"github.com/spaolacci/murmur3"

	"fmt"
	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
	murmur2 "github.com/aviddiviner/go-murmur"
	"math/rand"
	"time"
)

var log = logger.Get()

// ErrKeyNotFound is a standard error for when a key is not found in the storage engine
var ErrKeyNotFound = errors.New("key not found")

// Handler is a standard interface to a storage backend, used by
// AuthorisationManager to read and write key values to the backend
type Handler interface {
	GetKey(string) (string, error) // Returned string is expected to be a JSON object (user.SessionState)
	GetRawKey(string) (string, error)
	SetKey(string, string, int64) error // Second input string is expected to be a JSON object (user.SessionState)
	SetRawKey(string, string, int64) error
	SetExp(string, int64) error   // Set key expiration
	GetExp(string) (int64, error) // Returns expiry of a key
	GetKeys(string) []string
	DeleteKey(string) bool
	DeleteRawKey(string) bool
	Connect() bool
	GetKeysAndValues() map[string]string
	GetKeysAndValuesWithFilter(string) map[string]string
	DeleteKeys([]string) bool
	Decrement(string)
	IncrememntWithExpire(string, int64) int64
	SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{})
	GetSet(string) (map[string]string, error)
	AddToSet(string, string)
	AppendToSet(string, string)
	GetAndDeleteSet(string) []interface{}
	RemoveFromSet(string, string)
	DeleteScanMatch(string) bool
	GetKeyPrefix() string
	AddToSortedSet(string, string, float64)
	GetSortedSetRange(string, string, string) ([]string, []float64, error)
	RemoveSortedSetRange(string, string, string) error
}

func init() {
	// Set of indicators that a token is from a new hash function
	BuildRange(114, 414)
}

var HashRange []string

func BuildRange(min, max int) {
	top := max - min
	HashRange = make([]string, top)

	v := ""
	ind := 0
	for i := min; i < max; i++ {
		v = fmt.Sprintf("%x", i)
		if len(v) < 3 {
			v = "x" + v
		}

		HashRange[ind] = v
		ind++
	}

}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func ModifyFromHashRange(in string) string {
	rand.Seed(time.Now().UnixNano())
	n := rand.Int() % len(HashRange)

	out := in + HashRange[n]
	return out
}

func InRange(key string) bool {
	kLen := len(key)
	if kLen <= 56 {
		// old hashing method OrgID+Token or a custom token
		return false
	}

	// Check if tail in range
	lastThree := key[len(key)-3:]
	return stringInSlice(lastThree, HashRange)
}

// See https://softwareengineering.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
func HashMM2(in string) string {
	// Uses 64-bit hash that has good randomness
	h := murmur2.MurmurHash64A([]byte(in), 42)
	return fmt.Sprintf("%x", h)
}

func HashMM3(in string) string {
	h := murmur3.New32()
	h.Write([]byte(in))
	return hex.EncodeToString(h.Sum(nil))
}

func HashStr(in string) string {
	if InRange(in) {
		// use murmur2-based hash
		return HashMM2(in)
	}

	return HashMM3(in)
}

func HashKey(in string) string {
	if !config.Global().HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}
