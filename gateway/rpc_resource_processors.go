package gateway

import (
	"github.com/TykTechnologies/tyk/storage"
	"net/http"
	"strings"
)

type ResourceProcessor interface {
	Process(map[string]string)
}

type StandardKeysProcessor struct {
	synchronizerEnabled bool
	keysToReset         map[string]bool
	orgId               string
	rpcStorageHandler   *RPCStorageHandler
}

func (s *StandardKeysProcessor) Process(keys map[string]string) {
	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		_, resetQuota := s.keysToReset[splitKeys[0]]
		isHashed := len(splitKeys) > 1 && splitKeys[1] == "hashed"
		var status int
		if isHashed {
			log.Info("--> removing cached (hashed) key: ", splitKeys[0])
			key = splitKeys[0]
			_, status = s.rpcStorageHandler.Gw.handleDeleteHashedKey(key, s.orgId, "", resetQuota)
		} else {
			log.Info("--> removing cached key: ", key)
			// in case it's an username (basic auth) then generate the token
			if storage.TokenOrg(key) == "" {
				key = s.rpcStorageHandler.Gw.generateToken(s.orgId, key)
			}
			_, status = s.rpcStorageHandler.Gw.handleDeleteKey(key, s.orgId, "-1", resetQuota)
		}

		// if key not found locally and synchroniser disabled then we should not pull it from management layer
		if status == http.StatusNotFound && !s.synchronizerEnabled {
			continue
		}
		s.rpcStorageHandler.Gw.getSessionAndCreate(splitKeys[0], s.rpcStorageHandler, isHashed, s.orgId)
		s.rpcStorageHandler.Gw.SessionCache.Delete(key)
		s.rpcStorageHandler.Gw.RPCGlobalCache.Delete(s.rpcStorageHandler.KeyPrefix + key)
	}

}
