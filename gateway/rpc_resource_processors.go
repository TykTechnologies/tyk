package gateway

import (
	"github.com/TykTechnologies/tyk/storage"
	"net/http"
	"strings"
)

type ResourceProcessor interface {
	Process(map[string]string)
}

// StandardKeysProcessor process the messages from MDCB that corresponds to standard key changes
type StandardKeysProcessor struct {
	synchronizerEnabled bool
	keysToReset         map[string]bool
	orgId               string
	rpcStorageHandler   *RPCStorageHandler
}

// Process the standard keys changes
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

type OauthClientsProcessor struct {
	gw *Gateway
}

// Process performs the appropiate action for the received clients
// it can be any of the Create,Update and Delete operations
func (o *OauthClientsProcessor) Process(oauthClients map[string]string) {
	for clientInfo, action := range oauthClients {
		// clientInfo is: APIID.ClientID.OrgID
		eventValues := strings.Split(clientInfo, ".")
		apiId := eventValues[0]
		oauthClientId := eventValues[1]
		orgID := eventValues[2]

		o.processSingleOauthClientEvent(apiId, oauthClientId, orgID, action)
	}
}

func (o *OauthClientsProcessor) processSingleOauthClientEvent(apiId, oauthClientId, orgID, event string) {
	store, _, err := o.gw.GetStorageForApi(apiId)
	if err != nil {
		log.Error("Could not get oauth storage for api")
		return
	}

	switch event {
	case OauthClientAdded:
		// on add: pull from rpc and save it in local redis
		client, err := store.GetClient(oauthClientId)
		if err != nil {
			log.WithError(err).Error("Could not retrieve new oauth client information")
			return
		}

		err = store.SetClient(oauthClientId, orgID, client, false)
		if err != nil {
			log.WithError(err).Error("Could not save oauth client.")
			return
		}

		log.Info("oauth client created successfully")
	case OauthClientRemoved:
		// on remove: remove from local redis
		err := store.DeleteClient(oauthClientId, orgID, false)
		if err != nil {
			log.Errorf("Could not delete oauth client with id: %v", oauthClientId)
			return
		}
		log.Infof("Oauth Client deleted successfully")
	case OauthClientUpdated:
		// on update: delete from local redis and pull again from rpc
		_, err := store.GetClient(oauthClientId)
		if err != nil {
			log.WithError(err).Error("Could not retrieve oauth client information")
			return
		}

		err = store.DeleteClient(oauthClientId, orgID, false)
		if err != nil {
			log.WithError(err).Error("Could not delete oauth client")
			return
		}

		client, err := store.GetClient(oauthClientId)
		if err != nil {
			log.WithError(err).Error("Could not retrieve oauth client information")
			return
		}

		err = store.SetClient(oauthClientId, orgID, client, false)
		if err != nil {
			log.WithError(err).Error("Could not save oauth client.")
			return
		}
		log.Info("oauth client updated successfully")
	default:
		log.Warningf("Oauth client event not supported:%v", event)
	}
}

type CertificateProcessor struct {
	gw    *Gateway
	orgId string
}

func (c *CertificateProcessor) Process(certificates map[string]string) {

	for certId, action := range certificates {
		switch action {
		case CertificateAdded:
			log.Debugf("Adding certificate: %v", certId)
			//If we are in a slave node, MDCB Storage GetRaw should get the certificate from MDCB and cache it locally
			content, err := c.gw.CertificateManager.GetRaw(certId)
			if content == "" && err != nil {
				log.Debugf("Error getting certificate content")
			}
		case CertificateRemoved:
			log.Debugf("Removing certificate: %v", certId)
			c.gw.CertificateManager.Delete(certId, c.orgId)
			c.gw.RPCCertCache.Delete("cert-raw-" + certId)
		default:
			log.Debugf("ignoring certificate action: %v", action)
		}
	}
}
