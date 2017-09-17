package keygen

import (
	"strings"
	"github.com/satori/go.uuid"
	"encoding/base64"
)

type DefaultKeyGenerator struct{}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateAuthKey(orgID string) string {
	u5 := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	return orgID + cleanSting
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (DefaultKeyGenerator) GenerateHMACSecret() string {
	u5 := uuid.NewV4()
	cleanSting := strings.Replace(u5.String(), "-", "", -1)
	return base64.StdEncoding.EncodeToString([]byte(cleanSting))
}
