package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

// `{"` in base64
// SW-REQ-116
const B64JSONPrefix = "ey"

// SW-REQ-116
const DefaultHashAlgorithm = "murmur64"

// SW-REQ-116
const MongoBsonIdLength = 24

// GenerateToken generates a token.
// If hashing algorithm is empty, it uses legacy key generation.
// SW-REQ-116
func GenerateToken(orgID, keyID, hashAlgorithm string) (string, error) {
	if keyID == "" {
		keyID = uuid.NewHex()
	}

	if hashAlgorithm != "" {
		_, err := hashFunction(hashAlgorithm)
		if err != nil {
			hashAlgorithm = DefaultHashAlgorithm
		}

		jsonToken := fmt.Sprintf(`{"org":"%s","id":"%s","h":"%s"}`, orgID, keyID, hashAlgorithm)
		return base64.StdEncoding.EncodeToString([]byte(jsonToken)), err
	}

	// Legacy keys
	return orgID + keyID, nil
}

// SW-REQ-116
func TokenHashAlgo(token string) string {
	// Legacy tokens not b64 and not JSON records
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			hashAlgo, err := jsonparser.GetString(jsonToken, "h")

			if err != nil {
				logrus.Error(err)
				return ""
			}

			return hashAlgo
		}
	}

	return ""
}

// SW-REQ-116
func TokenID(token string) (id string, err error) {
	jsonToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}

	return jsonparser.GetString(jsonToken, "id")
}

// SW-REQ-116
func TokenOrg(token string) string {
	if strings.HasPrefix(token, B64JSONPrefix) {
		if jsonToken, err := base64.StdEncoding.DecodeString(token); err == nil {
			// Checking error in case if it is a legacy token which just by accided has the same b64JSON prefix
			if org, err := jsonparser.GetString(jsonToken, "org"); err == nil {
				return org
			}
		}
	}

	// 24 is mongo bson id length
	if len(token) > MongoBsonIdLength {
		newToken := token[:MongoBsonIdLength]
		_, err := hex.DecodeString(newToken)
		if err == nil {
			return newToken
		}
	}

	return ""
}
