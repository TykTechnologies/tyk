package license

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// PublicKeyPEM is the RSA public key in PEM format.
// It can be set at compile time using -ldflags.
var defaultPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA13oqkgO3RaYCMUxskU72
S5iBxTsc/KDNgcpoV3nujJuxRHC5jj3+bGaNMfpzMFCdzmtIjdkBnefLiCnqeGlT
CZCK627P1JT9ZRR9R6DGBk5Swr2ZXs0TefIR3HDJmtzBBGj63t9j6VTBYS7fnn2V
3MQG66cszXr6qPUpaN6EK61oGGs4517Ql1BzxGPdC8GJpr9teqgSLuFeeJwyqBqe
CxXxNjZ6OMjWqU2IT+lgUS97UbF1ep8iZJUdvwOmFBoWs6cY9SoTdzlzB4q90Kqs
tapRIa8HM7WWnwmI+i9uGl1QOmZfshOovOgzIZSJh1K43cdFSxgBvpO5ENyLeKai
ZwIDAQAB
-----END PUBLIC KEY-----`

var PublicKeyPEM = defaultPublicKeyPEM

// testMode indicates whether the license module is in test mode.
// When enabled, license validation is bypassed.
var testMode bool

// lic is the global license instance.
var lic *License
var licMutex sync.RWMutex // Mutex to protect concurrent access to lic

// License represents a parsed and validated license token.
type License struct {
	Token  *jwt.Token
	Scopes map[string]bool
}

// EnableTestMode enables the test mode.
func EnableTestMode() {
	licMutex.Lock()
	defer licMutex.Unlock()
	testMode = true
	if lic == nil {
		lic = &License{
			Scopes: make(map[string]bool),
		}
	}
}

// DisableTestMode disables the test mode.
func DisableTestMode() {
	licMutex.Lock()
	defer licMutex.Unlock()
	testMode = false
	lic = nil
}

// NewTestLicense creates a License instance with specified features for testing.
// It sets the global license instance to this test license.
func NewTestLicense(features []string) {
	licMutex.Lock()
	defer licMutex.Unlock()
	if !testMode {
		return
	}
	scopes := make(map[string]bool)
	for _, feature := range features {
		scopes[strings.TrimSpace(feature)] = true
	}
	lic = &License{
		Scopes: scopes,
	}
}

var timeNow = time.Now

// Load validates the license string and sets the global license instance.
// In test mode, it creates a license with no features unless set via NewTestLicense.
func Load(licenseString string) error {
	licMutex.Lock()
	defer licMutex.Unlock()

	// Trim spaces from the license string
	licenseString = strings.TrimSpace(licenseString)

	if licenseString == "" {
		return errors.New("license string is empty. Please set license_key in tyk.conf or TYK_GW_LICENSEKEY via environment variable")
	}

	if testMode {
		// In test mode, ensure lic is initialized
		if lic == nil {
			lic = &License{
				Scopes: make(map[string]bool),
			}
		}
		return nil
	}

	if PublicKeyPEM == "" {
		return errors.New("public key is not set")
	}

	// Parse the public key
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(PublicKeyPEM))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Parse and validate the token
	token, err := jwt.Parse(licenseString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return pubKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate standard claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			if int64(exp) < time.Now().Unix() {
				return errors.New("license has expired")
			}
		} else {
			return errors.New("exp claim is missing or invalid")
		}

		if nbf, ok := claims["nbf"].(float64); ok {
			if int64(nbf) > timeNow().Unix() {
				return errors.New("license not valid yet")
			}
		}

		// Extract scopes
		scopeStr, ok := claims["scope"].(string)
		if !ok {
			return errors.New("scope claim is missing or invalid")
		}

		scopes := make(map[string]bool)
		for _, scope := range strings.Split(scopeStr, ",") {
			scopes[strings.TrimSpace(scope)] = true
		}

		lic = &License{
			Token:  token,
			Scopes: scopes,
		}
		return nil
	} else {
		return errors.New("invalid token claims")
	}
}

// HasFeature checks if a feature is enabled in the global license.
// Returns false if the license is not loaded.
func HasFeature(feature string) bool {
	licMutex.RLock()
	defer licMutex.RUnlock()
	if lic == nil {
		return false
	}
	return lic.Scopes[feature]
}

// AddFeature adds a feature to the global license in test mode.
func AddFeature(feature string) {
	licMutex.Lock()
	defer licMutex.Unlock()
	if testMode && lic != nil {
		lic.Scopes[feature] = true
	}
}

// RemoveFeature removes a feature from the global license in test mode.
func RemoveFeature(feature string) {
	licMutex.Lock()
	defer licMutex.Unlock()
	if testMode && lic != nil {
		delete(lic.Scopes, feature)
	}
}
