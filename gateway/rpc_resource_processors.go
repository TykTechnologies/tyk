package gateway

import (
	"github.com/TykTechnologies/tyk/storage"
	"net/http"
	"strings"
)

// StandardKeysProcessor process the messages from MDCB that corresponds to standard key changes
type StandardKeysProcessor struct {
	synchronizerEnabled bool
	orgId               string
	rpcStorageHandler   *RPCStorageHandler
}

// Process the standard keys changes
func (s *StandardKeysProcessor) Process(events map[string]KeyEvent) {
	rpcHandler := s.rpcStorageHandler
	for _, event := range events {
		var status int
		if event.Hashed {
			log.Info("--> removing cached (hashed) key: ", event.KeyID)
			_, status = s.rpcStorageHandler.Gw.handleDeleteHashedKey(event.KeyID, s.orgId, "", event.ResetQuota)
		} else {
			log.Info("--> removing cached key: ", event.KeyID)
			// in case it's an username (basic auth) then generate the token
			if storage.TokenOrg(event.KeyID) == "" {
				event.KeyID = rpcHandler.Gw.generateToken(s.orgId, event.KeyID)
			}
			_, status = rpcHandler.Gw.handleDeleteKey(event.KeyID, s.orgId, "-1", event.ResetQuota)
		}

		// if key not found locally and synchroniser disabled then we should not pull it from management layer
		if status == http.StatusNotFound && !s.synchronizerEnabled {
			continue
		}
		rpcHandler.Gw.getSessionAndCreate(event.KeyID, rpcHandler, event.Hashed, s.orgId)
		flushKey(event.KeyID, s.rpcStorageHandler)
	}
}

type OauthClientsProcessor struct {
	gw                *Gateway
	orgId             string
	rpcStorageHandler *RPCStorageHandler
}

// Process performs the appropiate action for the received oauth events (tokens/clients)
func (o *OauthClientsProcessor) Process(oauthEvents []OauthEvent) {

	for _, v := range oauthEvents {
		switch v.EventType {
		case OAuthRevokeToken, OAuthRevokeAccessToken, OAuthRevokeRefreshToken:
			//key formed as: token:apiId:tokenActionTypeHint
			//but hashed as: token#hashed:apiId:tokenActionTypeHint
			hashedKey := strings.Contains(v.Token, "#hashed")
			if !hashedKey {
				storage, _, err := o.gw.GetStorageForApi(v.ApiId)
				if err != nil {
					continue
				}
				var tokenTypeHint string
				switch v.EventType {
				case OAuthRevokeAccessToken:
					tokenTypeHint = "access_token"
				case OAuthRevokeRefreshToken:
					tokenTypeHint = "refresh_token"
				}
				RevokeToken(storage, v.Token, tokenTypeHint)
			} else {
				v.Token = strings.Split(v.Token, "#")[0]
				o.gw.handleDeleteHashedKey(v.Token, o.orgId, v.ApiId, false)
			}
			flushKey(v.Token, o.rpcStorageHandler)
		case OAuthRevokeAllTokens:
			storage, _, err := o.gw.GetStorageForApi(v.ApiId)
			if err != nil {
				continue
			}

			_, tokens, _ := RevokeAllTokens(storage, v.ClientId, v.ClientSecret)
			for _, token := range tokens {
				flushKey(token, o.rpcStorageHandler)
			}

		case OauthClientAdded, OauthClientUpdated, OauthClientRemoved:
			o.processSingleOauthClientEvent(v.ApiId, v.ClientId, v.OrgId, v.EventType)
		}
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

func flushKey(keyID string, handler *RPCStorageHandler) {
	handler.Gw.SessionCache.Delete(keyID)
	handler.Gw.RPCGlobalCache.Delete(handler.KeyPrefix + keyID)
}
