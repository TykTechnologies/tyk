package gateway

import "strings"

type DefaultRPCResourceClassifier struct{}

type KeyEvent struct {
	KeyID      string
	ResetQuota bool
	Hashed     bool
}

type OauthEvent struct {
	ApiId        string
	OrgId        string
	ClientId     string
	ClientSecret string
	Token        string
	EventType    string
}

func (d *DefaultRPCResourceClassifier) classify(keys []string) (
	keyEvents map[string]KeyEvent,
	OauthEvents []OauthEvent,
	Certificates map[string]string) {

	keyEvents = map[string]KeyEvent{}
	OauthEvents = []OauthEvent{}
	Certificates = map[string]string{}

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 {
			action := splitKeys[len(splitKeys)-1]
			switch action {
			case ResetQuota, HashedKey:
				// key formatted as: {keyID:resetQuota} or {KeyId:hashed}
				isResetQuota := action == ResetQuota
				isHashed := action == HashedKey
				keyID := splitKeys[0]
				event, exists := keyEvents[keyID]
				if exists {
					// Update existing event
					if isResetQuota {
						event.ResetQuota = true
					}
					if isHashed {
						event.Hashed = true
					}
				} else {
					// otherwise add it
					event = KeyEvent{ResetQuota: isResetQuota, Hashed: isHashed, KeyID: keyID}
				}
				keyEvents[keyID] = event
			case CertificateRemoved, CertificateAdded:
				// key formatted as: {certId:action}
				certId := splitKeys[0]
				// k: certId v: CertificateRemoved or CertificateAdded
				Certificates[certId] = action
			case OAuthRevokeToken, OAuthRevokeAccessToken, OAuthRevokeRefreshToken:
				// key is formatted as {token:apiId:tokenTypeHint}
				//TokensToBeRevoked[splitKeys[0]] = key
				if len(splitKeys) != 3 {
					log.Error("not enough arguments to revoke oauth tokens")
					continue
				}

				event := OauthEvent{
					Token:     splitKeys[0],
					ApiId:     splitKeys[1],
					EventType: action,
				}
				OauthEvents = append(OauthEvents, event)
			case OAuthRevokeAllTokens:
				// key formatted as: {apiId:clientId:clientSecret:revoke_all_tokens}
				if len(splitKeys) != 4 {
					log.Error("not enough arguments to revoke client oauth tokens")
					continue
				}
				event := OauthEvent{
					ApiId:        splitKeys[0],
					ClientId:     splitKeys[1],
					ClientSecret: splitKeys[2],
					EventType:    action,
				}
				OauthEvents = append(OauthEvents, event)
				//ClientsToBeRevoked[splitKeys[1]] = key
			case OauthClientAdded, OauthClientUpdated, OauthClientRemoved:
				// key formatted as {apiId.clientId.orgId:action}
				// k: apiId.clientId.orgId, v: action
				//OauthClients[splitKeys[0]] = action
				oauthClientInfo := strings.Split(splitKeys[0], ".")
				if len(splitKeys) != 2 || len(oauthClientInfo) != 3 {
					log.Errorf("not enough arguments to process %v oauthClient", action)
					continue
				}
				event := OauthEvent{
					ApiId:     oauthClientInfo[0],
					ClientId:  oauthClientInfo[1],
					OrgId:     oauthClientInfo[2],
					EventType: action,
				}
				OauthEvents = append(OauthEvents, event)
			default:
				log.Debug("ignoring processing of action:", action)
			}
		} else {
			// no action defined, then it's just a key
			_, exists := keyEvents[key]
			if !exists {
				keyEvents[key] = KeyEvent{
					KeyID:      key,
					ResetQuota: false,
				}
			}
		}
	}
	return
}
