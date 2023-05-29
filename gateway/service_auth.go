package gateway

import (
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/gateway/service/auth"
	"github.com/TykTechnologies/tyk/storage"
)

type DefaultSessionManager = auth.SessionManager
type DefaultKeyGenerator = auth.KeyGenerator
type SessionHandler = auth.SessionHandler

func (gw *Gateway) ObfuscateKey(keyName string) string {
	if gw.GetConfig().EnableKeyLogging {
		return keyName
	}

	if len(keyName) > 4 {
		return "****" + keyName[len(keyName)-4:]
	}
	return "--"
}

func (gw *Gateway) GenerateToken(orgID, keyID string, customHashKeyFunction ...string) string {
	keyID = strings.TrimPrefix(keyID, orgID)
	hashKeyFunction := gw.GetConfig().HashKeyFunction

	if len(customHashKeyFunction) > 0 {
		hashKeyFunction = customHashKeyFunction[0]
	}

	token, err := storage.GenerateToken(orgID, keyID, hashKeyFunction)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "auth-mgr",
			"orgID":  orgID,
		}).WithError(err).Warning("Issue during token generation")
	}

	return token
}
