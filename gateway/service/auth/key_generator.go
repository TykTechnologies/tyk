package auth

import (
	"encoding/base64"

	"github.com/TykTechnologies/tyk/gateway/model"
	"github.com/TykTechnologies/tyk/internal/uuid"
)

type KeyGenerator struct {
	Gw model.GatewayInterface `json:"-"`
}

// GenerateAuthKey is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (d KeyGenerator) GenerateAuthKey(orgID string) string {
	return d.Gw.GenerateToken(orgID, "")
}

// GenerateHMACSecret is a utility function for generating new auth keys. Returns the storage key name and the actual key
func (KeyGenerator) GenerateHMACSecret() string {
	return base64.StdEncoding.EncodeToString([]byte(uuid.NewHex()))
}
